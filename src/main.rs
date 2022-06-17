extern crate ark_r1cs_std;
extern crate ark_relations;
extern crate ark_crypto_primitives;
extern crate ark_std;
extern crate rand;
extern crate ark_bls12_381;
extern crate ark_groth16;
extern crate ark_ff;

use ark_crypto_primitives::commitment::blake2s::Commitment;
use rand::{rngs::OsRng, Rng};

pub mod common;
use ark_crypto_primitives::CommitmentScheme;
use constraints::BoardVerifier;
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{generate_random_parameters, prepare_verifying_key, create_random_proof, verify_proof, Proof, PreparedVerifyingKey};
use ark_relations::r1cs::ToConstraintField;

mod constraints;


fn main() {
    let (board_size, num_ships)  = setup();
    println!("the board size is {} and the number of ships is {}", board_size, num_ships);


    // initialise playing boards.

    // player's own boards. 1 = battleship
    let mut board_a: Vec<u8> =  vec![0; board_size as usize];
    let mut board_b: Vec<u8> =  vec![0; board_size as usize];


    // views. 0 = unknown, 1 = hit, 2 = miss
    // player a's view of b's board
    let mut board_a_b: Vec<u8> = vec![0; board_size as usize];
    // player b's view of a's board
    let mut board_b_a: Vec<u8> = vec![0; board_size as usize];

    let (randomness_a, commitments_a, randomness_b, commitments_b) = initialise(board_size, num_ships, &mut board_a, &mut board_b);


    println!("Generating proof for player a");
    let (proof_a, pvk_a) = generate_proof(&board_a, &randomness_a, &commitments_a, num_ships, board_size);
    println!("Verifying proof..");
    let res = verify_initial_proof(&commitments_a, num_ships, board_size, proof_a, pvk_a);
    if res {
        println!("The proof was valid!");
    } else {
        println!("The proof was not valid.");
    }

    println!("Generating proof for player b");
    let (proof_b, pvk_b) = generate_proof(&board_b, &randomness_b, &commitments_b, num_ships, board_size);
    println!("Verifying proof..");
    let res2 = verify_initial_proof(&commitments_b, num_ships, board_size, proof_b, pvk_b);
    if res2 {
        println!("The proof was valid!");
    } else {
        println!("The proof was not valid.");
    }

    loop {
        // player a's turn
        println!("Player A's turn!");
        perform_turn(&mut board_b, &mut board_a_b, &randomness_b, &commitments_b);
        if check_winner(&mut board_b) {
            println!("Player One wins!");
            std::process::exit(0);
        }

        // player b's turn
        println!("Player B's turn!");
        perform_turn(&mut board_a, &mut board_b_a, &randomness_a, &commitments_a);
        if check_winner(&mut board_a) {
            println!("Player Two wins!");
            std::process::exit(0);
        }
    }
}

fn setup() -> (u8, u8) {
    println!("Please choose the size of the board. It must be a square number");
    let line = get_input();
    let board_size = line.trim().parse::<u8>().unwrap();

    println!("Please choose the the number of battleships. It must be less than the board size");
    let line = get_input();
    let num_ships = line.trim().parse::<u8>().unwrap();

    return (board_size, num_ships);
}

fn initialise(board_size: u8, num_ships: u8, board_a: &mut [u8], board_b: &mut [u8])
    -> (Vec<Vec<u8>>,Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>) {

    println!("The current game board size is {}!", &board_size);
    println!("Player 1 please place your battleships! You can place {} battleships.", &num_ships);
    place_battleships(board_a, num_ships);

    let randomness_a = generate_randomness(board_size);
    let commitments_a = generate_commitments(board_a, &randomness_a);


    println!("Player 2 please place your battleships! You can place {} battleships.", &num_ships);
    place_battleships(board_b, num_ships);
    let randomness_b = generate_randomness(board_size);
    let commitments_b = generate_commitments(board_b, &randomness_b);

    return (randomness_a, commitments_a, randomness_b, commitments_b)
}

/**
*   gets player input on where they want to place their battleships,
*   modifies the input board based on input
*   1 for battleship
*/
fn place_battleships(board: &mut [u8], num_ships: u8){
    for _n in 0..num_ships {
        board_to_string(board);
        println!("Type the corresponding number to position your battleship.");

        let line = get_input();
        let target = line.trim().parse::<usize>().unwrap();
        if target > board.len() {
            println!("Target not on board.")
        } else if board[target] == 0 {
            board[target] = 1;
        }
    }
    println!("----------------------------------------------------------------")
}

/**
*   generates 32 bytes of randomess board_size times and returns as Vec<Vec<u8>>
*/
fn generate_randomness(board_size: u8) -> Vec<Vec<u8>> {
    let mut randomness = Vec::new();
    for _ in 0..board_size {
        let mut rng = OsRng::default();
        let mut randomness_set = [0u8; 32];
        rng.fill(&mut randomness_set);
        randomness.push(randomness_set.to_vec());
    }
    return randomness;
}

/**
*   generates blake2s commitments for each board space using associated randomness
*/
fn generate_commitments(board: &[u8], randomness: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut commitments :Vec<Vec<u8>> = Vec::new();

    let params = ();
    for i in 0..board.len() {
        let mut r = [0u8;32];
        r.copy_from_slice(&randomness[i]);
        let commitment = Commitment::commit(&params, &[board[i]], &r );
        commitments.push(commitment.unwrap().to_vec());
    }
    return commitments;
}

/**
*   generates groth16 proof and verifying key
*/
fn generate_proof(board: &Vec<u8>, randomness: &Vec<Vec<u8>>, commitments: &Vec<Vec<u8>>, ships: u8, b_size: u8)
-> (Proof<Bls12_381>, PreparedVerifyingKey<Bls12_381>) {
    let circuit = BoardVerifier {
        ships: ships,
        b_size: b_size,
        commitments: commitments.clone(),

        rng_in: Some(randomness.clone()),
        board: Some(board.clone()),
    };

    let mut rng = OsRng::default();
    let params = generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng).unwrap();
    let pvk = prepare_verifying_key(&params.vk);


    let proof = {
        // Create a proof with our parameters.
        create_random_proof(circuit, &params, &mut rng).unwrap()
    };

    return (proof, pvk)
}

/**
* verifies proof using public information, the proof and the verifying key
*/
fn verify_initial_proof(commitments: &Vec<Vec<u8>>, ships: u8, b_size: u8, proof: Proof<Bls12_381>, pvk: PreparedVerifyingKey<Bls12_381>) -> bool {
    let  mut inputs: Vec<_> = Vec::new();
    inputs.push(Fr::from(ships));
    inputs.push(Fr::from(b_size));

    for i in commitments.clone() {
        let mut field_elements: Vec<Fr> = ToConstraintField::<Fr>::to_field_elements(&i).unwrap();
        inputs.append(&mut field_elements);
    }

    let r = verify_proof(&pvk, &proof, &inputs);
    return r.unwrap();
}

/**
* verifies tiles state by recalculating the commitment
*/
fn verify_move(ship: u8, randomness: &Vec<u8>, commitment: &Vec<u8>) {
    let mut rand = [0u8;32];
    rand.copy_from_slice(&randomness);
    let result = Commitment::commit(&(), &[ship], &rand);

    let mut comm = [0u8;32];
    comm.copy_from_slice(&commitment);

    let compare = result.unwrap() == comm;

    if compare {
        println!("The commitment is valid");
    } else {
        println!("The opposing player tried to cheat! You win.");
        std::process::exit(0);
    }
}


/**
*   prints out the board. Fills the board with 0, 1, ..., len-1
*/
fn board_to_string(board: &[u8]) {
    let mut output = "\n".to_string();
    let row_len = (board.len() as f64).sqrt() as usize;

    let mut rc = 0;
    let mut tc = 0;
    for tile in board {

        if rc == 0 {
            output += "[";
        }

        if tile == &(0 as u8) {
            output += &tc.to_string();
        } else if tile == &(1 as u8) {
            output += "o";
        } else if tile == &(2 as u8) {
            output += "x";
        }


        if rc == row_len-1 {
            output += "] \n";
            rc = 0;
        } else {
            output += ", ";
            rc += 1;
        }
        tc += 1;
    }

    print!("{}", output);
}

/**
*   Get one line of user input, return as a string
*/
fn get_input() -> String {
    let mut line = String::new();
    let _bytes = std::io::stdin().read_line(&mut line).unwrap();
    return line;
}

fn perform_turn(p_board: &mut [u8], view_board: &mut [u8], target_randomness: &Vec<Vec<u8>>, target_commitment: &Vec<Vec<u8>>) {
    println!("This is your view of the opponent's board. Pick a tile to attack");
    board_to_string(view_board);
    let t = get_input().trim().parse::<usize>().unwrap();

    if view_board[t] != 0 {
        println!("You have already attacked this area.");
        return
    }

    if (view_board[t] == 0) && (p_board[t] == 1) {
        println!("Hit!");
        println!("Verifying..");

        verify_move(1 ,&target_randomness[t] , &target_commitment[t]);

        view_board[t] = 2;
        p_board[t] = 0;
    }   else {
        println!("Miss!");
        verify_move(0 ,&target_randomness[t] , &target_commitment[t]);
        view_board[t] = 1;
    }
}

/**
*   Winner when board sum is zero.
*/
fn check_winner(board: &mut [u8]) -> bool {
    let mut sum = 0;
    for i in 0..board.len() {
        sum += board[i];
    }
    println!("Number of ships left is {}", sum);
    return sum == 0;
}