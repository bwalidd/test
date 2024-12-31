import { navigate } from '../index.js';
import Abstract from './Abstract.js';

function loadCSS(url) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = url;
    document.head.appendChild(link);
}

export default class GameAi extends Abstract {
    constructor(params) {
        loadCSS('../styles/GameAi.css');
        super(params);
        this.setTitle("Training");
        this.cssSelector = '../styles/GameAi.css';
    }

    async getHtml() {
        return `
        <div class="bod">
            <div class="game-header">
                <button class="game-instruction" id="game-instruction">Back to Home page</button>
            </div>
            <div class="game-container">
                <canvas id="pong" class="container" width="600" height="500"></canvas>
            </div>
        </div>
        `;
    }

    async initialize() {
        
        // Select Canvas
        const canvas = document.querySelector("#pong");
        const ctx = canvas.getContext("2d");

        // Game variables
        const SCORE_LIMIT = 3;
        const PLAYER_HEIGHT = 100;
        const PLAYER_WIDTH = 20;
        const BALL_START_SPEED = 1;
        const COM_LEVEL = 0.08;

        // Add a gameOver flag
        let gameOver = false;

        // Set canvas size explicitly
        canvas.width = 800;  // Adjust as needed
        canvas.height = 400; // Adjust as needed


        const net = {
            x: canvas.width / 2 - 1,
            y: 0,
            width: 2,
            height: 10,
            color: "RED",
        };

        const player = {
            x: 0,
            y: canvas.height / 2 - PLAYER_HEIGHT / 2,
            width: PLAYER_WIDTH,
            height: PLAYER_HEIGHT,
            color: "RED",
            score: 0,
        };

        const computer = {
            x: canvas.width - PLAYER_WIDTH,
            y: canvas.height / 2 - PLAYER_HEIGHT / 2,
            width: PLAYER_WIDTH,
            height: PLAYER_HEIGHT,
            color: "RED",
            score: 0,
        };

        const ball = {
            x: canvas.width / 2,
            y: canvas.height / 2,
            radius: 10,  // Reduced from 20 for better gameplay
            speed: BALL_START_SPEED,
            velocityX: 5,
            velocityY: 5,
            color: "GREEN",
        };

        // Draw shapes and text functions
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

        function gameover() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = "antiquewhite";
            ctx.font = "50px Ga Maamli";
            ctx.textAlign = "center";
            const winner = player.score >= SCORE_LIMIT ? "You" : "Computer";
            if (winner === "You")
                ctx.fillText("Congrats!!", canvas.width / 2, canvas.height / 2);
            else
                ctx.fillText("Game Over", canvas.width / 2, canvas.height / 2);
            ctx.font = "30px Ga Maamli";
            ctx.fillText(`${winner} Win!`, canvas.width / 2, canvas.height / 2 + 50);
        }

        // Redraw the canvas
        function render() {
            if (gameOver) {
                gameover(); // Call the gameOver function
                return; // Stop further rendering
            }        

            ctx.clearRect(0, 0, canvas.width, canvas.height)
            // Clear the canvas
            Rectdraw(0, 0, canvas.width, canvas.height, "#000");
            // Draw other elements
            Netdraw();
            // Draw score
            Textdraw(player.score, canvas.width / 4.5, canvas.height / 5, "RED");
            Textdraw(computer.score, (3 * canvas.width) / 4, canvas.height / 5, "RED");
            // Draw the player and computer
            Rectdraw(player.x, player.y, player.width, player.height, player.color);
            Rectdraw(computer.x, computer.y, computer.width, computer.height, computer.color);
            // Draw the ball
            Circledraw(ball.x, ball.y, ball.radius, ball.color);
        }

        // Update positions, score, etc.
        function Update() {

            //check if a player has reached the score limit
            if (player.score >= SCORE_LIMIT || computer.score >= SCORE_LIMIT) {
                gameOver = true;
            }

            // Ball movement
            ball.x += ball.velocityX * ball.speed;
            ball.y += ball.velocityY * ball.speed;

            // Ball collision with top and bottom borders
            if (ball.y + ball.radius > canvas.height || ball.y - ball.radius < 0) {
                ball.velocityY = -ball.velocityY;
            }

            // Ball collision with player or computer
            let selectedPlayer = ball.x < canvas.width / 2 ? player : computer;
            if (collision(ball, selectedPlayer)) {
                ball.velocityX = -ball.velocityX;
            }

            // Ball out of bounds
            if (ball.x - ball.radius < 0) {
                // Computer scores
                computer.score++;
                resetBall();
            } else if (ball.x + ball.radius > canvas.width) {
                // Player scores
                player.score++;
                resetBall();
            }

            // Move computer
            let targetPos = ball.y - computer.height / 2;
            computer.y = lerp(computer.y, targetPos, COM_LEVEL);
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

        // Loop
        const FPS = 60;
        setInterval(game, 1000 / FPS);
        const gameInterval = setInterval(game, 1000 / FPS);

        // Add mouse movement for player paddle
        canvas.addEventListener("mousemove", movePaddle);

        function movePaddle(e) {
            let rect = canvas.getBoundingClientRect();
            player.y = e.clientY - rect.top - player.height / 2;
        }

        document.getElementById("game-instruction").addEventListener("click", function () {
            clearInterval(gameInterval);
            
            navigate('/home');
        });
    
    }

    cleanup() {
        

        // Remove the dynamically added CSS
        const cssLink = document.querySelector(`link[href="${this.cssSelector}"]`);
        if (cssLink) {
            cssLink.remove();
        }

        // If you had event listeners or timers, clear them here
        // Example: Remove event listener
        // document.querySelector('.login-link')?.removeEventListener('click', this.someHandler);

        // Clear any temporary DOM elements or states
    }
}


