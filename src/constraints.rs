use crate::common::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{ToConstraintFieldGadget};
use ark_std::rand::Rng;
use ark_r1cs_std::fields::fp::FpVar;
use ark_crypto_primitives::{CommitmentGadget, CommitmentScheme};
use ark_crypto_primitives::commitment::blake2s::constraints::{CommGadget, RandomnessVar};
use ark_crypto_primitives::commitment::blake2s::Commitment;
use ark_crypto_primitives::prf::blake2s::constraints::OutputVar;


#[derive(Clone)]
pub struct BoardVerifier {
    // public
    pub ships: u8,
    pub b_size : u8,
    pub commitments: Vec<Vec<u8>>,

    // private
    pub board: Option<Vec<u8>>, // 0 for empty tile, 1 for battleship
    pub rng_in: Option<Vec<Vec<u8>>>,
}

impl ConstraintSynthesizer<ConstraintF> for BoardVerifier {
    fn generate_constraints(self, cs: ConstraintSystemRef<ConstraintF>) -> ark_relations::r1cs::Result<()> {

        // setup ship count
        let ships = FpVar::<ConstraintF>::new_input(ark_relations::ns!(cs, "ships"), || Ok(ConstraintF::from(self.ships)))?;

        // setup board size
        let b_size = FpVar::<ConstraintF>::new_input(ark_relations::ns!(cs, "b_size"), || Ok(ConstraintF::from(self.b_size)))?;

        // setup board
        let board = UInt8::new_witness_vec(ark_relations::ns!(cs, "board"),  self.board.as_ref().unwrap())?;
        let mut field_board: Vec<FpVar<ConstraintF>> = Vec::new();
        for i in board.clone() {
            let mut t = [i].to_constraint_field()?;
            field_board.push(t.pop().unwrap());
        }


        // check that the sum of the board is equal to num ships
        let mut board_sum = FpVar::zero();
        let mut board_len = FpVar::zero();
        for i in &field_board {
            board_sum = board_sum + i;
            board_len = board_len + FpVar::one();
        }

        let num_ships_correct = ships.is_eq(&board_sum)?;

        // check everything within the board is 0 or 1
        let mut values_are_valid: Boolean<ConstraintF> = Boolean::TRUE;
        for i in field_board.clone() {
            // true if i is zero or i is one
            values_are_valid = values_are_valid.and(&i.is_zero()?.or(&i.is_one()?)?)?;
        }

        // check board size is correct
        let board_size_correct = b_size.is_eq(&board_len)?;

        // setup rng
        let mut all_rng_witness = vec![];
        for rng_vec in self.rng_in.unwrap() {
            //let mut rng_witness = vec![];
            let rng_witness = UInt8::new_witness_vec(ark_relations::ns!(cs, "rng witness"), &rng_vec);
            let rng_witness = RandomnessVar(rng_witness.unwrap());
            all_rng_witness.push(rng_witness);
        }

        // setup commitments
        let mut all_comm_witness = vec![];
        for comm_vec in self.commitments {
            let comm_witness = UInt8::new_input_vec(ark_relations::ns!(cs, "commitment byte"), &comm_vec)?;
            let out = OutputVar(comm_witness);
            all_comm_witness.push(out);
        }


        let parameters = ();
        let parameters_var = <CommGadget as CommitmentGadget<Commitment, ConstraintF>>::ParametersVar::new_input(
            ark_relations::ns!(cs, "gadget_parameters"),
            || Ok(&parameters),
        ).unwrap();


        let mut results_vec = vec![];
        for i in 0..field_board.len() {
            let result_var = <CommGadget as CommitmentGadget<Commitment, ConstraintF>>::commit(
                &parameters_var,
                &[board[i].clone()],
                &all_rng_witness[i],
            ).unwrap();
            results_vec.push(result_var);
        }

        for i in 0..results_vec.len() {
            all_comm_witness[i].enforce_equal(&results_vec[i])?;
        }

        num_ships_correct.enforce_equal(&Boolean::TRUE)?;
        values_are_valid.enforce_equal(&Boolean::TRUE)?;
        board_size_correct.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

// you probably want to comment this test out as it takes a LONG time to run
#[test]
fn benchmark(){
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use tracing_subscriber::layer::SubscriberExt;
    use ark_groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };
    use ark_bls12_381::{Bls12_381, Fr};
    use std::time::Instant;
    use ark_ff::{ToConstraintField};

    let board_sizes = [4, 9, 16, 25, 36, 49, 64, 81, 100];

    for size in board_sizes {
        let mut board: Vec<u8> = vec![0; size];
        board[0] = 1;
        board[1] = 1;
        board[2] = 1;

        let mut rng = ark_std::test_rng();
        let mut randomness:Vec<Vec<u8>> = Vec::new();


        let params = ();
        let mut comms:Vec<Vec<u8>> = Vec::new();
        for i in 0..board.len() {
            let mut rand = [0u8; 32];
            rng.fill(&mut rand);
            randomness.push(rand.to_vec());
            comms.push(Commitment::commit(&params, &[board[i]], &rand).unwrap().to_vec());
        }

        let circuit = BoardVerifier {
            ships: 3,
            b_size: size as u8,
            commitments: comms.clone(),

            rng_in: Some(randomness),
            board: Some(board),
        };


        let start = Instant::now();

        let params = generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng).unwrap();
        let pvk = prepare_verifying_key(&params.vk);

        println!("Setup time for {}: {}", size, start.elapsed().as_secs());
        println!("{}", pvk.vk.gamma_abc_g1.len());
        let start = Instant::now();

        let proof = {
            // Create a proof with our parameters.
            create_random_proof(circuit, &params, &mut rng).unwrap()
        };

        println!("Proving time for {}: {}", size, start.elapsed().as_secs());

        let  mut inputs: Vec<_> = Vec::new();
        inputs.push(Fr::from(3));
        inputs.push(Fr::from(size as u8));

        for i in comms {
            let mut field_elements: Vec<Fr> = ToConstraintField::<Fr>::to_field_elements(&i).unwrap();
            inputs.append(&mut field_elements);
        }

        let start = Instant::now();
        // Check the proof
        let r = verify_proof(&pvk, &proof, &inputs).unwrap();

        assert!(r);
        println!("Verifying time for {}: {}", size, start.elapsed().as_millis());
    }

}


#[test]
fn test_zk() {
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use tracing_subscriber::layer::SubscriberExt;
    use ark_groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::{ToConstraintField};


    let board: Vec<u8> = vec![1,1,1,0,0,0,0,0,0];

    let mut rng = ark_std::test_rng();
    let mut randomness:Vec<Vec<u8>> = Vec::new();


    let params = ();
    let mut comms:Vec<Vec<u8>> = Vec::new();
    for i in 0..board.len() {
        let mut rand = [0u8; 32];
        rng.fill(&mut rand);
        randomness.push(rand.to_vec());
        comms.push(Commitment::commit(&params, &[board[i]], &rand).unwrap().to_vec());
    }

    let circuit = BoardVerifier {
        ships: 3,
        b_size: 9,
        commitments: comms.clone(),

        rng_in: Some(randomness),
        board: Some(board),
    };


    let params = generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng).unwrap();
    let pvk = prepare_verifying_key(&params.vk);


    let proof = {
        // Create a proof with our parameters.
        create_random_proof(circuit, &params, &mut rng).unwrap()
    };

    let  mut inputs: Vec<_> = Vec::new();
    inputs.push(Fr::from(3));
    inputs.push(Fr::from(9));

    for i in comms {
        let mut field_elements: Vec<Fr> = ToConstraintField::<Fr>::to_field_elements(&i).unwrap();
        inputs.append(&mut field_elements);
    }

    // Check the proof
    let r = verify_proof(&pvk, &proof, &inputs).unwrap();
    assert!(r);
}


#[test]
fn constraints_test() {
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use tracing_subscriber::layer::SubscriberExt;

    let board: Vec<u8> = vec![1,1,1,0,0,0,0,0,0];

    let mut rng = ark_std::test_rng();
    let mut randomness:Vec<Vec<u8>> = Vec::new();


    let params = ();
    let mut comms:Vec<Vec<u8>> = Vec::new();
    for i in 0..board.len() {
        let mut rand = [0u8; 32];
        rng.fill(&mut rand);
        randomness.push(rand.to_vec());
        comms.push(Commitment::commit(&params, &[board[i]], &rand).unwrap().to_vec());
    }

    let circuit = BoardVerifier {
        ships: 3,
        b_size: 9,
        commitments: comms,

        rng_in: Some(randomness),
        board: Some(board),
    };

    // First, some boilerplate that helps with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Next, let's make the circuit!
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();

    if !is_satisfied {
        // If it isn't, find out the offending constraint.
        println!("{:?}", cs.which_is_unsatisfied());
    }
    assert!(is_satisfied);
}

#[test]
fn test_incorrect_ships() {
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use tracing_subscriber::layer::SubscriberExt;

    let board: Vec<u8> = vec![1,1,1,0,0,0,0,0,0];
    let mut rng = ark_std::test_rng();
    let mut randomness:Vec<Vec<u8>> = Vec::new();

    let params = ();
    let mut comms:Vec<Vec<u8>> = Vec::new();
    for i in 0..board.len() {
        let mut rand = [0u8; 32];
        rng.fill(&mut rand);
        randomness.push(rand.to_vec());
        comms.push(Commitment::commit(&params, &[board[i]], &rand).unwrap().to_vec());
    }


    let circuit = BoardVerifier {
        ships: 4,
        b_size: 9,
        commitments: comms,
        board: Some(board),
        rng_in: Some(randomness),
    };

    // First, some boilerplate that helps with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Next, let's make the circuit!
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();

    assert!(!is_satisfied);
}

#[test]
fn test_incorrect_size() {
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use tracing_subscriber::layer::SubscriberExt;

    let board: Vec<u8> = vec![1,1,1,0,0,0,0,0,0];
    let mut rng = ark_std::test_rng();
    let mut randomness:Vec<Vec<u8>> = Vec::new();

    let params = ();
    let mut comms:Vec<Vec<u8>> = Vec::new();
    for i in 0..board.len() {
        let mut rand = [0u8; 32];
        rng.fill(&mut rand);
        randomness.push(rand.to_vec());
        comms.push(Commitment::commit(&params, &[board[i]], &rand).unwrap().to_vec());
    }


    let circuit = BoardVerifier {
        ships: 3,
        b_size: 10,
        commitments: comms,
        board: Some(board),
        rng_in: Some(randomness),
    };

    // First, some boilerplate that helps with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Next, let's make the circuit!
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();

    assert!(!is_satisfied);
}

#[test]
fn test_ships_same_as_size() {
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use tracing_subscriber::layer::SubscriberExt;

    let board: Vec<u8> = vec![1,1,1,1,1,1,1,1,1];
    let mut rng = ark_std::test_rng();
    let mut randomness:Vec<Vec<u8>> = Vec::new();

    let params = ();
    let mut comms:Vec<Vec<u8>> = Vec::new();
    for i in 0..board.len() {
        let mut rand = [0u8; 32];
        rng.fill(&mut rand);
        randomness.push(rand.to_vec());
        comms.push(Commitment::commit(&params, &[board[i]], &rand).unwrap().to_vec());
    }


    let circuit = BoardVerifier {
        ships: 9,
        b_size: 9,
        commitments: comms,
        board: Some(board),
        rng_in: Some(randomness),
    };

    // First, some boilerplate that helps with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Next, let's make the circuit!
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();

    assert!(is_satisfied);
}

#[test]
fn test_no_ships() {
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use tracing_subscriber::layer::SubscriberExt;

    let board: Vec<u8> = vec![0,0,0,0,0,0,0,0,0];
    let mut rng = ark_std::test_rng();
    let mut randomness:Vec<Vec<u8>> = Vec::new();

    let params = ();
    let mut comms:Vec<Vec<u8>> = Vec::new();
    for i in 0..board.len() {
        let mut rand = [0u8; 32];
        rng.fill(&mut rand);
        randomness.push(rand.to_vec());
        comms.push(Commitment::commit(&params, &[board[i]], &rand).unwrap().to_vec());
    }


    let circuit = BoardVerifier {
        ships: 0,
        b_size: 9,
        commitments: comms,
        board: Some(board),
        rng_in: Some(randomness),
    };

    // First, some boilerplate that helps with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Next, let's make the circuit!
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();

    assert!(is_satisfied);
}

#[test]
fn test_incorrect_board_value() {
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use tracing_subscriber::layer::SubscriberExt;

    let board: Vec<u8> = vec![2,0,0,0,0,0,0,0,0];
    let mut rng = ark_std::test_rng();
    let mut randomness:Vec<Vec<u8>> = Vec::new();

    let params = ();
    let mut comms:Vec<Vec<u8>> = Vec::new();
    for i in 0..board.len() {
        let mut rand = [0u8; 32];
        rng.fill(&mut rand);
        randomness.push(rand.to_vec());
        comms.push(Commitment::commit(&params, &[board[i]], &rand).unwrap().to_vec());
    }


    let circuit = BoardVerifier {
        ships: 1,
        b_size: 9,
        commitments: comms,
        board: Some(board),
        rng_in: Some(randomness),
    };

    // First, some boilerplate that helps with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Next, let's make the circuit!
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();

    assert!(!is_satisfied);
}

#[test]
fn test_incorrect_board_value_no_ships() {
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use tracing_subscriber::layer::SubscriberExt;

    let board: Vec<u8> = vec![2,0,0,0,0,0,0,0,0];
    let mut rng = ark_std::test_rng();
    let mut randomness:Vec<Vec<u8>> = Vec::new();

    let params = ();
    let mut comms:Vec<Vec<u8>> = Vec::new();
    for i in 0..board.len() {
        let mut rand = [0u8; 32];
        rng.fill(&mut rand);
        randomness.push(rand.to_vec());
        comms.push(Commitment::commit(&params, &[board[i]], &rand).unwrap().to_vec());
    }


    let circuit = BoardVerifier {
        ships: 0,
        b_size: 9,
        commitments: comms,
        board: Some(board),
        rng_in: Some(randomness),
    };

    // First, some boilerplate that helps with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Next, let's make the circuit!
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();

    assert!(!is_satisfied);
}