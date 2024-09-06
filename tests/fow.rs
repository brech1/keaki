//! # Fog of War
//!
//! This test implements a two-player "tag" game with a fog of war mechanic, where players can only see their own position and adjacent tiles on a grid-based board.
//!
//! ## Objective
//!
//! The goal is for one player to find the other player's hidden position. Players take turns checking if their opponent is in view and moving to adjacent tiles if not.
//!
//! The game ends when one player decrypts the location of the other, indicating they are within visible range, thus winning the game.
//!
//! ## Game Mechanics
//!
//! - Each player starts at opposite ends of the board.
//! - Players can only see their position and the adjacent tiles around them.
//! - Each turn, a player attempts to decrypt the opponent's position. If successful, the game ends.
//! - If the opponent's position is not visible, the player moves to a random adjacent tile.
//! - This continues until one player finds the opponent’s position and wins.
//!
//! ## Cryptographic Setup
//!
//! The game utilizes WE to encrypt each player’s position. Players can only decrypt opponent positions when they are in or near visible range.
//!
//! - **KZG Commitment**: Both players commit their positions on the board using KZG, based on a polynomial interpolation of the position vector (1 at their position, 0 elsewhere).
//! - **Encryption**: Each player encrypts their position using the opponent’s commitment, for it's position and all adjacent tiles.
//! - **Decryption**: The player generates an opening proof for their position and attempts to decrypt the opponent's encrypted position ciphertexts.
//! - **Move**: If the opponent's position is not visible, the player moves to a random adjacent tile, updates their position, commits, and re-encrypts their position.
//!
//! ## Running the Simulation
//!
//! The current test simulates a match between two players, Alice and Bob. The game progresses through turns until one player wins.
//!
//! To run the simulation:
//!
//! ```bash
//! cargo test test_fog_of_war_game -- --nocapture
//! ```
//!

use ark_bls12_381::{
    g1::{G1_GENERATOR_X, G1_GENERATOR_Y},
    g2::{G2_GENERATOR_X, G2_GENERATOR_Y},
    Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective,
};
use keaki::{kem::KEM, kzg::KZG, pol_op::lagrange_interpolation, we::WE};
use rand::{seq::IteratorRandom, thread_rng};

pub const BOARD_SIZE: usize = 4;
pub const BOARD_TILES: usize = BOARD_SIZE * BOARD_SIZE;

// Starting Positions
// A - - - - -
// - - - - - -
// - - - - - -
// - - - - - -
// - - - - - -
// - - - - - B

const ALICE_STARTING_POS: usize = 0;
const BOB_STARTING_POS: usize = BOARD_TILES - 1;
const MESSAGE: &[u8] = b"I'm here!";

/// Board
#[derive(Debug, Clone)]
pub struct Board {
    pub tiles: Vec<u8>,
}

impl Board {
    pub fn new() -> Self {
        Self {
            tiles: vec![0; BOARD_TILES],
        }
    }

    /// Returns all valid adjacent positions indices for a given position
    pub fn get_adjacent_positions(pos: usize) -> Vec<usize> {
        let row = pos as isize / BOARD_SIZE as isize;
        let col = pos as isize % BOARD_SIZE as isize;

        let deltas: [(isize, isize); 8] = [
            (-1, -1), // Top-left
            (-1, 0),  // Up
            (-1, 1),  // Top-right
            (0, -1),  // Left
            (0, 1),   // Right
            (1, -1),  // Bottom-left
            (1, 0),   // Down
            (1, 1),   // Bottom-right
        ];

        // Collect valid adjacent positions
        let mut valid_positions = Vec::new();
        for (drow, dcol) in deltas.iter() {
            let new_row = row + drow;
            let new_col = col + dcol;

            // Check if the new position is within vec bounds
            if new_row >= 0
                && new_row < BOARD_SIZE as isize
                && new_col >= 0
                && new_col < BOARD_SIZE as isize
            {
                let new_pos = (new_row * BOARD_SIZE as isize + new_col) as usize;
                valid_positions.push(new_pos);
            }
        }

        valid_positions
    }

    /// Returns a random adjacent position
    pub fn get_random_adjacent_pos(pos: usize) -> usize {
        let adj_positions = Board::get_adjacent_positions(pos);
        adj_positions
            .into_iter()
            .choose(&mut thread_rng())
            .expect("No valid moves available. This should not happen.")
    }

    /// Displays the current board, showing the player's position and the opponent's position if provided
    pub fn display(player_pos: usize, opponent_pos: Option<usize>, step: u32) {
        println!("\nStep {}: Player's View", step);

        for i in 0..BOARD_SIZE {
            for j in 0..BOARD_SIZE {
                let idx = i * BOARD_SIZE + j;

                if idx == player_pos {
                    print!(" X "); // Player's position
                } else if let Some(op_pos) = opponent_pos {
                    if idx == op_pos {
                        print!(" O ");
                    } else {
                        print!(" . ");
                    }
                } else {
                    print!(" . ");
                }
            }
            println!();
        }
    }
}

/// Game Struct
pub struct Game {
    // Extractable WE
    pub we: WE<Bls12_381>,
    // Alice's position
    pub alice_pos: usize,
    // Bob's position
    pub bob_pos: usize,
    // Alice's commitment
    pub alice_com: G1Projective,
    // Bob's commitment
    pub bob_com: G1Projective,
    // Encrypted Alice's position
    pub alice_enc_pos: Vec<(G2Projective, Vec<u8>)>,
    // Encrypted Bob's position
    pub bob_enc_pos: Vec<(G2Projective, Vec<u8>)>,
    // Current step
    pub step: u32,
    // Is game finished
    pub finished: bool,
}

impl Game {
    /// Game setup
    pub fn new(secret: Fr) -> Self {
        // Setup kzg
        let g1_generator = G1Affine::new(G1_GENERATOR_X, G1_GENERATOR_Y);
        let g2_generator = G2Affine::new(G2_GENERATOR_X, G2_GENERATOR_Y);
        let max_degree = BOARD_TILES;
        let kzg: KZG<Bls12_381> =
            KZG::setup(g1_generator.into(), g2_generator.into(), max_degree, secret);
        let kem: KEM<Bls12_381> = KEM::new(kzg);
        let we: WE<Bls12_381> = WE::new(kem);

        println!("Alice's starting position: {}", ALICE_STARTING_POS);
        println!("Bob's starting position: {}", BOB_STARTING_POS);

        let alice_adjacents = Board::get_adjacent_positions(ALICE_STARTING_POS);
        let bob_adjacents = Board::get_adjacent_positions(BOB_STARTING_POS);

        println!("Alice's adjacent positions: {:?}", alice_adjacents);
        println!("Bob's adjacent positions: {:?}", bob_adjacents);

        // These alphas are 1 for the player's position and adjacent positions
        // Are used to encrypt the player's position using the opponent's commitment
        let mut alice_alphas = Vec::new();
        alice_alphas.push(Fr::from(ALICE_STARTING_POS as u32));
        for &val in alice_adjacents.iter() {
            alice_alphas.push(Fr::from(val as u32));
        }
        let alice_alphas_len = alice_alphas.len();

        let mut bob_alphas = Vec::new();
        bob_alphas.push(Fr::from(BOB_STARTING_POS as u32));
        for &val in bob_adjacents.iter() {
            bob_alphas.push(Fr::from(val as u32));
        }
        let bob_alphas_len = bob_alphas.len();

        // This full alpha array represents the whole board, so we have an enumerating vec of 1 to BOARD_TILES
        let mut players_full_alphas = vec![Fr::from(0); BOARD_TILES];
        for i in 0..BOARD_TILES {
            players_full_alphas[i] = Fr::from(i as u32);
        }

        // These vectors will be one at the position of the player and zero elsewhere
        let mut alice_full_betas = vec![Fr::from(0); BOARD_TILES];
        alice_full_betas[ALICE_STARTING_POS] = Fr::from(1);
        let mut bob_full_betas = vec![Fr::from(0); BOARD_TILES];
        bob_full_betas[BOB_STARTING_POS] = Fr::from(1);

        // Generate commiting polynomial
        let alice_pol =
            lagrange_interpolation::<Bls12_381>(&players_full_alphas, &alice_full_betas).unwrap();
        let bob_pol =
            lagrange_interpolation::<Bls12_381>(&players_full_alphas, &bob_full_betas).unwrap();

        // Commit to Alice and Bob's initial positions
        let alice_com = we.kem().kzg().commit(&alice_pol).unwrap();
        let bob_com = we.kem().kzg().commit(&bob_pol).unwrap();

        // Important: We should verify that alice is providing correct encryptions of her position and vice versa somehow.

        // Embed the player's position in the message
        let mut alice_message = Vec::from(MESSAGE);
        alice_message.push(ALICE_STARTING_POS as u8);
        let mut bob_message = Vec::from(MESSAGE);
        bob_message.push(BOB_STARTING_POS as u8);

        // Encrypt the player's position using the opponent's commitment
        let alice_enc_pos = we
            .encrypt(
                bob_com,
                alice_alphas,
                vec![Fr::from(1); alice_alphas_len],
                &alice_message,
            )
            .unwrap();
        let bob_enc_pos = we
            .encrypt(
                alice_com,
                bob_alphas,
                vec![Fr::from(1); bob_alphas_len],
                &bob_message,
            )
            .unwrap();

        Self {
            we,
            alice_pos: ALICE_STARTING_POS,
            bob_pos: BOB_STARTING_POS,
            alice_com,
            bob_com,
            alice_enc_pos,
            bob_enc_pos,
            step: 0,
            finished: false,
        }
    }

    /// Game logic
    pub fn next(&mut self) -> () {
        if self.finished {
            return;
        }

        let is_alice_turn = self.step % 2 == 0;

        println!(
            "\nTurn {}: It's {}'s turn!",
            self.step,
            if is_alice_turn { "Alice" } else { "Bob" }
        );

        match self.try_decrypt_opponent_position(is_alice_turn) {
            Some(pos) => {
                if is_alice_turn {
                    println!("Alice wins!");
                    Board::display(self.alice_pos, Some(pos as usize), self.step);
                } else {
                    println!("Bob wins!");
                    Board::display(self.bob_pos, Some(pos as usize), self.step);
                }

                self.finished = true;
                return;
            }
            None => {
                println!("Opponent's position is not visible.");
                self.move_player(is_alice_turn);
            }
        }

        self.step += 1;
    }

    /// Attempts to decrypt the opponent's position. Returns true if successful (opponent is visible).
    pub fn try_decrypt_opponent_position(&self, is_alice_turn: bool) -> Option<u8> {
        let (opponent_enc_pos, player_pos) = if is_alice_turn {
            (&self.bob_enc_pos, self.alice_pos)
        } else {
            (&self.alice_enc_pos, self.bob_pos)
        };
        let player_adjacents = Board::get_adjacent_positions(player_pos);

        println!("Decrypting opponent's position...");
        println!("Player's position: {}", player_pos);
        println!("Player's adjacent positions: {:?}", player_adjacents);

        let mut player_full_alphas = vec![Fr::from(0); BOARD_TILES];
        for i in 0..BOARD_TILES {
            player_full_alphas[i] = Fr::from(i as u32);
        }

        // This vector will be one at the position of the player and zero elsewhere
        let mut player_full_betas = vec![Fr::from(0); BOARD_TILES];
        player_full_betas[player_pos] = Fr::from(1);

        // Interpolate
        let player_pol =
            lagrange_interpolation::<Bls12_381>(&player_full_alphas, &player_full_betas).unwrap();

        // Generate a single proof for the player's position
        let proof = self
            .we
            .kem()
            .kzg()
            .open(&player_pol, &Fr::from(player_pos as u32))
            .unwrap();

        for (key_ct, msg_ct) in opponent_enc_pos {
            let msg = self.we.decrypt_single(proof, *key_ct, msg_ct).unwrap();

            if msg.starts_with(MESSAGE) {
                println!("Decryption successful!");

                // Get the opponent's position
                let op_pos = *msg.last().unwrap();

                println!("Opponent's position: {}", op_pos);
                return Some(op_pos);
            }
        }

        None
    }

    /// Moves the current player to a random adjacent position.
    pub fn move_player(&mut self, is_alice_turn: bool) {
        let (opponent_com, player_pos) = if is_alice_turn {
            (self.bob_com, self.alice_pos)
        } else {
            (self.alice_com, self.bob_pos)
        };

        // Get new position
        let new_pos = Board::get_random_adjacent_pos(player_pos);

        // Display the new position
        println!("Player moved to: {}", new_pos);
        let player_adjacents = Board::get_adjacent_positions(new_pos);
        println!("Player's adjacent positions: {:?}", player_adjacents);
        Board::display(new_pos, None, self.step);

        // Prepare alphas (indices where player position is 1)
        let mut player_alphas = Vec::new();
        player_alphas.push(Fr::from(new_pos as u32));
        for &val in player_adjacents.iter() {
            player_alphas.push(Fr::from(val as u32));
        }
        let player_alphas_len = player_alphas.len();

        let mut player_full_alphas = vec![Fr::from(0); BOARD_TILES];
        for i in 0..BOARD_TILES {
            player_full_alphas[i] = Fr::from(i as u32);
        }

        // This vector will be one at the position of the player and zero elsewhere
        let mut player_full_betas = vec![Fr::from(0); BOARD_TILES];
        player_full_betas[new_pos] = Fr::from(1);

        // Interpolate
        let player_full_pol =
            lagrange_interpolation::<Bls12_381>(&player_full_alphas, &player_full_betas).unwrap();

        // Commit to the new position
        let player_com = self.we.kem().kzg().commit(&player_full_pol).unwrap();

        // Encrypt the new position vector using the opponent's commitment
        let mut player_message = Vec::from(MESSAGE);
        player_message.push(new_pos as u8);

        let enc_pos = self
            .we
            .encrypt(
                opponent_com,
                player_alphas,
                vec![Fr::from(1); player_alphas_len],
                &player_message,
            )
            .unwrap();

        // Update the player's encrypted position and commitment
        if is_alice_turn {
            self.alice_enc_pos = enc_pos;
            self.alice_com = player_com;
            self.alice_pos = new_pos;
        } else {
            self.bob_enc_pos = enc_pos;
            self.bob_com = player_com;
            self.bob_pos = new_pos;
        }
    }
}

#[cfg(test)]
mod fow_tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::{test_rng, UniformRand};

    #[test]
    fn test_fog_of_war_game() {
        // Setup secret
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);

        // Initialize the game
        let mut game = Game::new(secret);

        // Simulate a few turns
        while !game.finished {
            game.next();
        }

        assert!(true);
    }
}
