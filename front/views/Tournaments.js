import { navigate } from '../index.js';
import Abstract from './Abstract.js';
import { fetchUserData } from './authutils.js';

function loadCSS(url) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = url;
    document.head.appendChild(link);
}

export default class Tournaments extends Abstract {
    constructor(params) {
        loadCSS('../styles/Tournament.css');
        super(params);
        this.setTitle("Tournaments");
		this.currentUser = null;
		this.cssSelector = "../styles/Tournament.css";
		this.players = [];
    }

	async getHtml() {
		this.currentUser = await fetchUserData('http://localhost:8001/api/auth/user/');

        console.log("the user : ", this.currentUser.login);

		const winnersKey = `tournamentWinners_${this.currentUser.login}`;
		const playersKey = `tournamentPlayers_${this.currentUser.login}`;

		const winners = JSON.parse(localStorage.getItem(winnersKey)) || [];
		this.players = JSON.parse(localStorage.getItem(playersKey)) || [];
	
		//if no players, show input form
		if (this.players.length === 0) {
			return `
			<div class="bodyy">
				<div class="overlay"></div>
				<div class="tournament-container">
					<h1>Create Tournament</h1>
					<div class="form-container">
						<label for="player1">Player 1:</label>
						<input type="text" id="player1" placeholder="Enter name of Player 1">
						
						<label for="player2">Player 2:</label>
						<input type="text" id="player2" placeholder="Enter name of Player 2">
						
						<label for="player3">Player 3:</label>
						<input type="text" id="player3" placeholder="Enter name of Player 3">
						
						<label for="player4">Player 4:</label>
						<input type="text" id="player4" placeholder="Enter name of Player 4">
						
						<button id="generateTournament" class="generate-btn">Generate</button>
					</div>
					<a href="/">Back To Home Page</a>
					
				</div>
				<div class="tournament-map" id="tournamentMap">
					<!-- Tournament map will be dynamically added here -->
				</div>
			</div>
			`;
		}

		//Render match buttons based on stored winners and players
		const renderMatchButtons = () => {
			const winners = JSON.parse(localStorage.getItem(`tournamentWinners_${this.currentUser.login}`)) || [];
		
			const getWinnerText = (stage, defaultText) => {
				const winner = winners.find(w => w.stage === stage);
				return winner ? `Winner: ${winner.winner}` : defaultText;
			};

            // Function to determine button classes based on match status
			const getButtonClasses = (stage) => {
				const winner = winners.find(w => w.stage === stage);
				if (winner) {
					return 'match-btn match-completed';
				}
				return 'match-btn';
			};

			const firstSemiFinalButton = `
				<h2>Semi-Final 1: </h2>
				<button class="${getButtonClasses('first')}" data-stage="first" data-players="${this.players[0]},${this.players[1]}" ${winners.some(w => w.stage === 'first') ? 'disabled' : ''}>
					<span> ${getWinnerText('first', `${this.players[0]} vs ${this.players[1]}`)} </span>
				</button>
			`;

			const secondSemiFinalButton = `
				<h2>Semi-Final 2: </h2>
				<button class="${getButtonClasses('second')}" data-stage="second" data-players="${this.players[2]},${this.players[3]}" ${winners.some(w => w.stage === 'second') ? 'disabled' : ''}>
					<span> ${getWinnerText('second', `${this.players[2]} vs ${this.players[3]}`)} </span>
				</button>
			`;
		
			const firstWinner = winners.find(w => w.stage === 'first');
			const secondWinner = winners.find(w => w.stage === 'second');
		
			let finalMatchButton;
			if (firstWinner && secondWinner) {
				const finalWinner = winners.find(w => w.stage === 'final');
				finalMatchButton = `
					<h2>Final: </h2>
					<button class="${getButtonClasses('final')} final" data-stage="final" data-players="${firstWinner.winner},${secondWinner.winner}" ${finalWinner ? 'disabled' : ''}>
						${finalWinner 
							? `Winner: ${finalWinner.winner}` 
							: `${firstWinner.winner} vs ${secondWinner.winner}`}
					</button>
				`;
			} else {
				// Final match button when semi-finals are not complete
				finalMatchButton = `
					<h2>Final: </h2>
					<button class="match-btn final final-not-ready" data-stage="final" disabled>
						<span>${firstWinner ? firstWinner.winner : 'Winner of 1st match'} vs ${secondWinner ? secondWinner.winner : 'Winner of 2nd match'} </span>
					</button>
				`;
			}
		
			return `${firstSemiFinalButton}${secondSemiFinalButton}${finalMatchButton}`;
		};
		
		return `
		<div class="bodyy">
			<div class="overlay"></div>
			<div class="tournament-container">
				<div class="tournament-matches">
					<h1>Tournament Matches</h1>
					<div class="match-buttons">
						${renderMatchButtons()}
					</div>
					<button id="quitTournament" class="quit-btn">Quit Tournament</button>
				</div>
			</div>
			<div class="tournament-map" id="tournamentMap">
				<!-- Tournament map will be dynamically added here -->
			</div>
		</div>
		`;
	}
    async initialize() {
		try {
			this.currentUser = await fetchUserData('http://localhost:8001/api/auth/user/');
	
			if (!this.currentUser) {
				this.showAlert('Please log in to create a tournament');
				navigate('/login');
				return;
			}

			// Use user-specific key for players
			const playersKey = `tournamentPlayers_${this.currentUser.login}`;
			this.players = JSON.parse(localStorage.getItem(playersKey)) || [];
	
			if (this.players.length === 0) {
				this.setupTournamentGeneration();
			} else {
				this.setupMatchSelection();
				this.setupQuitButton();
			}
		} catch (error) {
			console.error('Failed to fetch user data:', error);
			this.showAlert('Failed to load user data. Please log in again.');
			navigate('/login');
		}
	}

	setupTournamentGeneration() {
		const button = document.querySelector('#generateTournament');

		if (!button) {
			console.error('Generate Tournament button not found');
			return;
		}
	
		button.addEventListener('click', () => {
			const playerInputs = ['player1', 'player2', 'player3', 'player4'].map(id => {
					const element = document.getElementById(id);
					return element ? element.value.trim() : '';
				});
	
			//validate inputs
			if (playerInputs.some(p => !p) || new Set(playerInputs).size < 4) {
				this.showAlert('Please fill unique player names!');
				return;
			} else if (playerInputs.some(p => p.length > 15) || playerInputs.some(p => p.length < 2) ) {
				this.showAlert('Player names with a number of characters between 2 and 10');
				return;
			}

			// Store players with user-specific key
			const playersKey = `tournamentPlayers_${this.currentUser.login}`;
			localStorage.setItem(playersKey, JSON.stringify(playerInputs));
			
			// Remove any existing winners
			const winnersKey = `tournamentWinners_${this.currentUser.login}`;
			localStorage.removeItem(winnersKey);
	
			//Reload to show matches
			window.location.reload();
		});
	}

	setupMatchSelection() {
		const matchButtons = document.querySelectorAll('.match-btn');
		const winners = JSON.parse(localStorage.getItem(`tournamentWinners_${this.currentUser.login}`)) || [];
		// console.log("these are winners : ", winners);

		matchButtons.forEach(button => {
			// Check if the button should be disabled
			const stage = button.dataset.stage;
			if (winners.some(w => w.stage === stage)) {
				button.disabled = true;
			}

			// Enable/disable final match button based on semi-final winners
			if (stage === 'final') {
				const firstWinner = winners.find(w => w.stage === 'first');
				const secondWinner = winners.find(w => w.stage === 'second');
				
				if (!firstWinner || !secondWinner) {
					button.disabled = true;
				}
			}

			button.addEventListener('click', () => {
				const players = button.dataset.players.split(',');
				const stage = button.dataset.stage;

				//set current match details
				localStorage.setItem(`currentMatch_${this.currentUser.login}`, JSON.stringify({
					playerA: players[0],
					playerB: players[1],
					stage: stage,
					winner: ''
				}));

				//Navigate to game
				navigate('/friendly');
			});

		});
	}

	setupQuitButton() {
        const quitButton = document.getElementById('quitTournament');

        if (quitButton) {
            quitButton.addEventListener('click', () => {
                const playersKey = `tournamentPlayers_${this.currentUser.login}`;
                const winnersKey = `tournamentWinners_${this.currentUser.login}`;
				const currentMatch = `currentMatch_${this.currentUser.login}`;

                localStorage.removeItem(playersKey);
                localStorage.removeItem(winnersKey);
				localStorage.removeItem(currentMatch);

                navigate('/tournaments');
            });
        }
    }	

    // Helper function to show alerts
    showAlert(message) {
        const alertBox = document.createElement('div');
        alertBox.className = 'custom-alert';
        alertBox.innerText = message;
        document.body.appendChild(alertBox);
    
        // Remove the alert after 3 seconds
        setTimeout(() => alertBox.remove(), 3000);
    }

	cleanup() {
        // Remove the dynamically added CSS
        const cssLink = document.querySelector(`link[href="${this.cssSelector}"]`);
        if (cssLink) {
            cssLink.remove();
        }
    }
    
}


