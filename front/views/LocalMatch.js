import { navigate } from '../index.js';
import Abstract from './Abstract.js';
import { fetchUserData } from './authutils.js';

function loadCSS(url) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = url;
    document.head.appendChild(link);
}

export default class LocalMatch extends Abstract {
    constructor(params) {
        loadCSS('../styles/LocalMatch.css');
        super(params);
        this.setTitle("Friendly Match");
        this.currentUser = null;
        // this.currentMatch = '';
        this.cssSelector = "../styles/LocalMatch.css"
    }

    async getHtml() {
        this.currentUser = await fetchUserData('http://localhost:8001/api/auth/user/');
        const current_match = `currentMatch_${this.currentUser.login}`;
        console.log("here is the current match: ", current_match)

        if (!this.currentUser) {
            this.showAlert('Please log in to start a match');
            navigate('/');
            return;
        }

        //verify current match belongs to this user
        const currentMatch = JSON.parse(localStorage.getItem(current_match));
        if (!currentMatch) {
            console.error("No current match found or match does not belong to current user.");
            navigate('/');
            return;
        }

        //Ensure user is loaded
        if (!this.currentUser) {
            return `<div>Loading...</div>`;
        }

        //Rest of the existing getHtml method
        return `
        <div class="bodyy">
            <div class="overlay"></div>
            <div class="game-container">
                <button class="game-instruction" id="game-instruction">Back to Home page</button>
                <canvas id="pong" class="canvas-container"></canvas>
                <div class="player-names" id="players">
                    <div class="player-name">${currentMatch.playerA} : w/s</div>
                    <div class="player-name">${currentMatch.playerB} : ↑/↓</div>
                </div>
            </div>
        </div>
        `;
    }


    async initialize() {
        // try {
            //feth user data
            this.currentUser = await fetchUserData('http://localhost:8001/api/auth/user/');
            const current_match = `currentMatch_${this.currentUser.login}`;
            const tournament_winners = `tournamentWinners_${this.currentUser.login}`;

            if (!this.currentUser) {
                this.showAlert('Please log in to start a match');
                navigate('/');
                return;
            }

            //verify current match belongs to this user
            const currentMatch = JSON.parse(localStorage.getItem(current_match));
            if (!currentMatch) {
                console.error("No current match found or match does not belong to current user.");
                navigate('/');
                return;
            }

            const canvas = document.querySelector("#pong");
            const ctx = canvas.getContext("2d");

            // Game variables
            const SCORE_LIMIT = 1;
            const PLAYER_HEIGHT = 100;
            const PLAYER_WIDTH = 10;
            const BALL_START_SPEED = 1;
            const SPEED_INCREMENT_INTERVAL = 10000; // Increase speed every 10 seconds
            const SPEED_INCREMENT_AMOUNT = 0.2;

            // Get the width and height from CSS
            const canvasWidth = parseInt(window.getComputedStyle(canvas).width, 10);
            const canvasHeight = parseInt(window.getComputedStyle(canvas).height, 10);

            // Apply the CSS width and height to the canvas
            canvas.width = canvasWidth;
            canvas.height = canvasHeight;

            const net = {
                x: canvas.width / 2 - 1,
                y: 0,
                width: 2,
                height: 10,
                color: "WHITE",
            };

            const player1 = {
                x: 0,
                y: canvas.height / 2 - PLAYER_HEIGHT / 2,
                width: PLAYER_WIDTH,
                height: PLAYER_HEIGHT,
                color: "WHITE",
                score: 0,
                name: currentMatch.playerA
            };

            const player2 = {
                x: canvas.width - PLAYER_WIDTH,
                y: canvas.height / 2 - PLAYER_HEIGHT / 2,
                width: PLAYER_WIDTH,
                height: PLAYER_HEIGHT,
                color: "WHITE",
                score: 0,
                name: currentMatch.playerB
            };

            const ball = {
                x: canvas.width / 2,
                y: canvas.height / 2,
                radius: 10,
                speed: BALL_START_SPEED,
                velocityX: 5,
                velocityY: 5,
                color: "#e20303e8",
            };

            function Rectdraw(x, y, w, h, color) {
                ctx.fillStyle = color;
                ctx.fillRect(x, y, w, h);
            }

            function Circledraw(x, y, r, color) {
                ctx.fillStyle = color;
                ctx.beginPath();
                ctx.arc(x, y, r, 0, Math.PI * 2, false);
                ctx.closePath();
                ctx.fill();
            }

            function Textdraw(text, x, y, color) {
                ctx.fillStyle = color;
                ctx.font = "45px Arial";
                ctx.fillText(text, x, y);
            }

            function Netdraw() {
                for (let i = 0; i <= canvas.height; i += 15) {
                    Rectdraw(net.x, net.y + i, net.width, net.height, net.color);
                }
            }

            function collision(b, p) {
                return (
                    b.x + b.radius > p.x &&
                    b.x - b.radius < p.x + p.width &&
                    b.y + b.radius > p.y &&
                    b.y - b.radius < p.y + p.height
                );
            }

            function lerp(start, end, amount) {
                return (1 - amount) * start + amount * end;
            }

            let gameOverTriggered = false; // Add a flag to prevent multiple executions

            function gameover() {
                if (gameOverTriggered) return; // Exit if the function has already been called
                gameOverTriggered = true; // Set the flag to true
            
                // Clear the canvas and display the winner
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                ctx.fillStyle = "antiquewhite";
                ctx.font = "50px Ga Maamli";
                ctx.textAlign = "center";
            
                const winner = player1.score >= SCORE_LIMIT ? player1.name : player2.name;
                // localStorage.setItem(current_match, JSON.stringify({ winner }));
                ctx.fillText(`${winner} Wins!`, canvas.width / 2, canvas.height / 2);
            
                // Update tournamentWinners in localStorage
                const winnersKey = tournament_winners;
                const tournamentWinners = JSON.parse(localStorage.getItem(winnersKey)) || [];
                tournamentWinners.push({ stage: currentMatch.stage, winner });
                localStorage.setItem(winnersKey, JSON.stringify(tournamentWinners));
            
                // localStorage.removeItem(current_match); // Clear current match data
            
                // Remove any existing tournament buttons before adding a new one
                const existingButton = document.querySelector('.go-to-tournament-btn');
                if (existingButton) {
                    existingButton.remove();
                }
            
                const button = document.createElement('button');
                button.innerText = 'Go to Tournament';
        
                const parent = document.getElementById('players')
                
                const targetChild = parent.children[1]; // Assuming you want to insert before the second child

                if (targetChild) {
                    parent.insertBefore(button, targetChild);
                } else {
                    parent.appendChild(button);
                }

                // Set up the button click handler to navigate to the tournament page
                button.addEventListener('click', () => {
                    navigate('/tournaments');
                    button.remove();
                });
            }

        // } catch (error) {
        //     console.error('Failed to fetch user data: ', error);
        //     this.showAlert('Failed to load user data, Please log in again.');
        //     navigate('/');
        // }
        

        let gameOver = false; // Global flag to track the game state

        function render() {
            if (gameOver) {
                gameover(); // Call the game over logic once
                return;
            }

            ctx.clearRect(0, 0, canvas.width, canvas.height);
            Rectdraw(0, 0, canvas.width, canvas.height, "#000");
            Netdraw();
            Textdraw(player1.score, canvas.width / 5, canvas.height / 5, "WHITE");
            Textdraw(player2.score, (3 * canvas.width) / 4, canvas.height / 5, "WHITE");
            Rectdraw(player1.x, player1.y, player1.width, player1.height, player1.color);
            Rectdraw(player2.x, player2.y, player2.width, player2.height, player2.color);
            Circledraw(ball.x, ball.y, ball.radius, ball.color);
        }

        function Update() {
            if (gameOver) return; // Prevent further updates if the game is over

            // Check if the game should end
            if (player1.score >= SCORE_LIMIT || player2.score >= SCORE_LIMIT) {
                gameOver = true;
                return; // Stop further updates and rendering
            }

            ball.x += ball.velocityX * ball.speed;
            ball.y += ball.velocityY * ball.speed;

            // Handle ball collision with the top and bottom walls
            if (ball.y + ball.radius > canvas.height || ball.y - ball.radius < 0) {
                ball.velocityY = -ball.velocityY;
            }

            // Handle ball collision with players
            const selectedPlayer = ball.x < canvas.width / 2 ? player1 : player2;
            if (collision(ball, selectedPlayer)) {
                ball.velocityX = -ball.velocityX;
            }

            // Update scores and reset ball position
            if (ball.x - ball.radius < 0) {
                player2.score++;
                resetBall();
            } else if (ball.x + ball.radius > canvas.width) {
                player1.score++;
                resetBall();
            }
        }

        function resetBall() {
            ball.x = canvas.width / 2;
            ball.y = canvas.height / 2;
            ball.velocityX = -ball.velocityX;
            ball.speed = BALL_START_SPEED;
        }

        function game() {
            Update();
            render();
        }

        // Speed up the ball every SPEED_INCREMENT_INTERVAL
        setInterval(() => {
            if (!gameOver) {
                ball.speed += SPEED_INCREMENT_AMOUNT;
            }
        }, SPEED_INCREMENT_INTERVAL);

        const FPS = 60;
        setInterval(game, 1000 / FPS);

        // Player controls
        window.addEventListener("keydown", (event) => {
            switch (event.key) {
                case "ArrowUp":
                    player2.y = Math.max(player2.y - 20, 0);
                    break;
                case "ArrowDown":
                    player2.y = Math.min(player2.y + 20, canvas.height - player2.height);
                    break;
                case "w":
                    player1.y = Math.max(player1.y - 20, 0);
                    break;
                case "s":
                    player1.y = Math.min(player1.y + 20, canvas.height - player1.height);
                    break;
            }
        });

        document.getElementById("game-instruction").addEventListener("click", function () {
            navigate('/home');
        });
    }

    cleanup() {
        // Remove the dynamically added CSS
        const cssLink = document.querySelector(`link[href="${this.cssSelector}"]`);
        if (cssLink) {
            cssLink.remove();
        }
    }
    
}
