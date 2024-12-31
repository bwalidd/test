import { navigate } from '../index.js';
import Abstract from './Abstract.js';

function loadCSS(url) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = url;
    document.head.appendChild(link);
}

export default class GameRemote extends Abstract {
    constructor(params) {
        super(params);
        loadCSS('../styles/GameRemote.css');
        this.setTitle("Friendly Match");
        this.currentPlayer = null;
        this.currentUsername = null;
        this.leftuser = null;
        this.gameCanvas = null;
        this.ctx = null;
        this.player1 = null;
        this.player2 = null;
        this.ball = null;
        this.ws = null;
        this.checkDisconnectionStatus();
        this.SCORE_LIMIT = 4;
        this.gameOver = false;  
        this.data_of_players = null;    
        this.cssSelector = '../styles/GameRemote.css';
    }

    async getHtml() {
        return `
        <div class="informations">
            <div class="right-div">
                <div id="my-username-avatar" class="avatar"></div>
                <h2 id="my-username">Logged username</h2>
            </div>
            <div class="left-div">
                <h2 id="friend-username">Friend username</h2>
                <div id="friend-username-avatar" class="avatar"></div>
            </div>
        </div>
        <div class="game-header">
            <button class="game-instruction" id="game-instruction">Back to Home page</button>
        </div>
        <div class="game-container">
            <canvas id="pong" class="container" width="800" height="400"></canvas>
        </div>
        `;
    }


    async getCsrfToken() {
        const name = 'csrftoken=';
        const cookies = document.cookie.split(';');
        for (let cookie of cookies) {
            cookie = cookie.trim();
            if (cookie.indexOf(name) === 0) {
                return cookie.substring(name.length);
            }
        }
        return null;
    }

    checkDisconnectionStatus() {
        const disconnectionInfo = JSON.parse(localStorage.getItem('gameDisconnectionInfo') || '{}');
        
        // Check if there's a disconnection flag for this session
        if (disconnectionInfo.sessionId === localStorage.getItem('currentSessionId')) {
            // Clear the flag after processing
            localStorage.removeItem('gameDisconnectionInfo');
            
            // Display disconnection message
            // this.displayGameOverMessageDis(disconnectionInfo.winner);
            this.alreadyDisconnected();

            // Remove current session ID
            console.log('Session ID removed from here');
            localStorage.removeItem('currentSessionId');
            
            // Prevent further game interactions
            this.gameOver = true;
        }
    }

    alreadyDisconnected() {
        const existingOverlay = document.querySelector('.game-over-overlay');
         if (existingOverlay) {
             existingOverlay.remove();
         }
 
         // Create main overlay div
         const overlay = document.createElement('div');
         overlay.className = 'game-over-overlay';
         
         // Styling for the overlay
         Object.assign(overlay.style, {
             position: 'fixed',
             top: '50%',
             left: '50%',
             transform: 'translate(-50%, -50%)',
             width: '60%',
             height: '50%',
             background: 'linear-gradient(135deg, rgba(0, 0, 0, 0.8), rgba(40, 40, 40, 0.9))',
             color: '#FFD700', // Gold text color
             display: 'flex',
             flexDirection: 'column',
             justifyContent: 'center',
             alignItems: 'center',
             textAlign: 'center',
             borderRadius: '15px',
             boxShadow: '0 4px 20px rgba(0, 0, 0, 0.7)',
             fontFamily: 'Arial, sans-serif',
             zIndex: '1000',
             animation: 'fadeIn 0.5s ease-in-out'
         });
 
         // Create fade-in animation
         const fadeInStyleSheet = document.createElement('style');
         fadeInStyleSheet.type = 'text/css';
         fadeInStyleSheet.innerHTML = `
             @keyframes fadeIn {
                 from { opacity: 0; }
                 to { opacity: 1; }
             }
         `;
         document.head.appendChild(fadeInStyleSheet);
 
         // Create message container
         const messageDiv = document.createElement('div');
         messageDiv.className = 'game-over-message';
         Object.assign(messageDiv.style, {
             display: 'flex',
             flexDirection: 'column',
             justifyContent: 'center'
         });
 
         // Set innerHTML with dynamic winner and styled elements
         messageDiv.innerHTML = `
             <h2 style="font-size: 1.5rem; font-weight: bold; margin: 0;">You Lost the Match because You Disconnect</h2>
             <a id="game-over-btn" href="/" style="
                 display: inline-block;
                 padding: 15px 30px;
                 font-size: 1rem;
                 margin-top: 20px;
                 background: linear-gradient(90deg, #FF4500, #FF6347);
                 color: white;
                 text-decoration: none;
                 border: none;
                 border-radius: 8px;
                 cursor: pointer;
                 transition: background 0.3s, transform 0.2s;
             ">Back to Home</a>
         `;
 
         // Create hover effect for the button
         const buttonHoverStyle = document.createElement('style');
         buttonHoverStyle.type = 'text/css';
         buttonHoverStyle.innerHTML = `
             #game-over-btn:hover {
                 background: linear-gradient(90deg, #FF6347, #FF4500);
                 transform: scale(1.05);
             }
         `;
         document.head.appendChild(buttonHoverStyle);
 
         // Add event listener to handle navigation
         const homeButton = messageDiv.querySelector('#game-over-btn');
         homeButton.addEventListener('click', (e) => {
             e.preventDefault(); // Prevent default link behavior
             
             // Remove the overlay
             overlay.remove();
             
             // Remove the added style elements
             fadeInStyleSheet.remove();
             buttonHoverStyle.remove();
             
             // Navigate to home page
             navigate('/');
         });
 
         // Append message to overlay and overlay to body
         overlay.appendChild(messageDiv);
         document.body.appendChild(overlay);
 
         // Optional: Add a way to close the overlay by clicking outside
         overlay.addEventListener('click', (e) => {
             if (e.target === overlay) {
                 overlay.remove();
                 fadeInStyleSheet.remove();
                 buttonHoverStyle.remove();
             }
         });
    }


    async initialize() {
        this.leftuser = null;
        try {
            const sessionId = localStorage.getItem("currentSessionId");
            console.log("Session ID from localStorage:", sessionId);
    
            if (sessionId) {
                await this.initializeGameSession(sessionId); // Ensure game session is fully initialized
                this.setupGameEnvironment();
            } else {
                // console.error("No sessionId found in localStorage.");
            }
        } catch (error) {
            console.error("Error during initialization:", error);
        }
    }
    

    // new
    async initializeGameSession(sessionId) {
        try {
            // Show a temporary notification
            this.showTemporaryNotification("Getting ready... Please wait!");
    
            // Introduce a delay (e.g., 1 seconds)
            await new Promise(resolve => setTimeout(resolve, 1500));
    
            const csrfToken = await this.getCsrfToken();
            const response = await fetch(`http://localhost:8001/api/game/details/${sessionId}/`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                credentials: 'include'
            });
    
            if (!response.ok) {
                throw new Error('Failed to fetch game session details');
            }
    
            this.data_of_players = await response.json();
            console.log('Game session details:', this.data_of_players);
    
            // Proceed with other operations
            await Promise.all([
                this.fetchAndDisplayUserInfo(this.data_of_players.player_one, "my-username"),
                this.fetchAndDisplayUserInfo(this.data_of_players.player_two, "friend-username")
            ]);
    
            this.leftuser = document.getElementById('my-username').textContent;
            this.currentUsername = await this.checkWhoLoggedIn();
    
            this.currentUsername = await this.checkWhoLoggedIn();
            console.log('Current user is:------->', this.currentUsername);
            console.log('Left user is:------->', this.leftuser);
    
            if (this.currentUsername === this.leftuser) {
                this.currentPlayer = 'player_one';
                console.log('Current player is player_one');
            } else {
                this.currentPlayer = 'player_two';
                console.log('Current player is player_two');
            }
    
        } catch (error) {
            console.error("Error in initializeGameSession:", error);
            throw error;
        }
    }
    


   
    showTemporaryNotification(message) {
        // Create the overlay
        const overlay = document.createElement("div");
        overlay.style.position = "fixed";
        overlay.style.top = "0";
        overlay.style.left = "0";
        overlay.style.width = "100%";
        overlay.style.height = "100%";
        overlay.style.backgroundColor = "rgba(0, 0, 0, 0.8)"; // Semi-transparent black
        overlay.style.zIndex = "999"; // Behind the notification
        document.body.appendChild(overlay);
    
        // Create the notification
        const notification = document.createElement("div");
        notification.textContent = message;
    
        // Apply styles for the notification
        notification.style.position = "fixed";
        notification.style.top = "50%";
        notification.style.left = "50%";
        notification.style.transform = "translate(-50%, -50%)";
        notification.style.padding = "20px 30px";
        notification.style.background = "linear-gradient(270deg, darkred, black)";
        notification.style.color = "antiquewhite";
        notification.style.fontFamily = "'Ga Maamli', sans-serif";
        notification.style.fontSize = "18px";
        notification.style.borderRadius = "5px";
        notification.style.boxShadow = "0 4px 8px rgba(0, 0, 0, 0.2)";
        notification.style.zIndex = "1000"; // Above the overlay
        document.body.appendChild(notification);
    
        // Remove the overlay and notification after 3 seconds
        setTimeout(() => {
            overlay.remove();
            notification.remove();
        }, 1500);
    }
    


   
    
    
    
    async checkWhoLoggedIn() {
        try{
            const csrfToken = await this.getCsrfToken();
            const response = await fetch('http://localhost:8001/api/auth/user/', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                credentials: 'include'
            });
            
            const data = await response.json();
    
            return data.login;
        }catch (error) {
            console.error("Error in checkWhoLoggedIn:", error);
        }

    }

    async fetchAndDisplayUserInfo(username, elementId) {
        try {
            const csrfToken = await this.getCsrfToken();
            const response = await fetch(`http://localhost:8001/api/auth/user/${username}/`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error('Failed to fetch user profile');
            }

            const data = await response.json();
            console.log('-------------------------/ ', data);
            document.getElementById(elementId).textContent = data.login;


            // const userAvatar = data.image || '/default-avatar.png';
            const userAvatar = data.isIntraUser ? data.image : `http://localhost:8001${data.avatar}`;
            console.log('User avatar:', userAvatar);

            if (elementId === "my-username") {
                localStorage.setItem('my-username', data.login);
            } else if (elementId === "friend-username") {
                localStorage.setItem('friend-username', data.login);
            }

            document.getElementById(`${elementId}-avatar`).style.backgroundImage = `url('${userAvatar}')`;
        } catch (error) {
            console.error(`Error in fetchAndDisplayUserInfo for ${elementId}:`, error);
            throw error;
        }
    }

    gameLoop() {
        this.updateBallPosition();
        this.render();
        requestAnimationFrame(() => this.gameLoop());
    }

    updateBallPosition() {
        if (this.gameOver) return;

        // Move the ball
        this.ball.x += this.ball.velocityX;
        this.ball.y += this.ball.velocityY;
    
        // Ball collision with top and bottom walls
        if (this.ball.y + this.ball.radius > this.gameCanvas.height || this.ball.y - this.ball.radius < 0) {
            this.ball.velocityY = -this.ball.velocityY; // Reverse vertical direction
        }
    
        // Ball collision with paddles
        if (
            this.ball.x - this.ball.radius < this.player1.x + this.player1.width && // Left paddle
            this.ball.y > this.player1.y && this.ball.y < this.player1.y + this.player1.height
        ) {
            this.ball.velocityX = -this.ball.velocityX; // Reverse horizontal direction
        }
    
        if (
            this.ball.x + this.ball.radius > this.player2.x && // Right paddle
            this.ball.y > this.player2.y && this.ball.y < this.player2.y + this.player2.height
        ) {
            this.ball.velocityX = -this.ball.velocityX; // Reverse horizontal direction
        }
    
        // Ball out of bounds (scoring)
        if (this.ball.x + this.ball.radius < 0) {
            this.player2.score++; // Player 2 scores
            this.broadcastScoreUpdate(); // Synchronize score
            this.checkGameOver();
            this.resetBall();     // Reset ball position
        }
    
        if (this.ball.x - this.ball.radius > this.gameCanvas.width) {
            this.player1.score++; // Player 1 scores
            this.broadcastScoreUpdate(); // Synchronize score
            this.checkGameOver();
            this.resetBall();     // Reset ball position
        }
    }


    broadcastScoreUpdate() {
        // Send synchronized score update via WebSocket
        this.ws.send(JSON.stringify({
            action: "score_update",
            player1_score: this.player1.score,
            player2_score: this.player2.score
        }));
    }

    checkGameOver() {
        if (this.player1.score >= this.SCORE_LIMIT || this.player2.score >= this.SCORE_LIMIT) {
            this.gameOver = true;
            const winner = this.player1.score >= this.SCORE_LIMIT ? 
                localStorage.getItem('my-username') : 
                localStorage.getItem('friend-username');
            
            // Send game over message via WebSocket
            this.ws.send(JSON.stringify({
                action: "game_over",
                winner: winner
            }));
            
            // Display game over message
            if (this.leftuser === this.currentUsername) {
                console.log('i will store data ----->',this.leftuser);
                this.collectdataToSave(winner);
            }
            this.displayGameOverMessage(winner);
            localStorage.removeItem('currentSessionId');

        }
    }

    async sendToStoreData(winner) {
        try {
            const csrfToken = await this.getCsrfToken(); // Ensure this method retrieves the CSRF token properly
            const new_session = localStorage.getItem('newSession'); // Use the correct session key
            
            console.log('new_session---->', new_session);
            console.log('csrfToken--->', csrfToken);
    
            if (!new_session) { // Check new_session instead of session
                console.error("No current session ID found in local storage.");
                return;
            }
    
            const response = await fetch(`http://localhost:8001/api/game/result/${new_session}/`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                credentials: 'include',
                body: JSON.stringify({
                    winner: winner,
                    score_player_1: this.player1.score,
                    score_player_2: this.player2.score
                }),
            });
    
            if (!response.ok) {
                const errorData = await response.json();
                console.error("Failed to post game result:", errorData);
            } else {
                const result = await response.json();
                console.log("Game result successfully posted:", result);
                localStorage.removeItem('newSession');
            }
        } catch (error) {
            console.error("An error occurred while posting game result:", error);
        }
    }

    async sendToStoreDataDis(winner, player, session) {
        try {
            const csrfToken = await this.getCsrfToken(); // Ensure this method retrieves the CSRF token properly
            if (!session) { // Check new_session instead of session
                console.error("No current session ID found in local storage.");
                return;
            }
    
            if (player === 'player_one') {
                this.player1.score = 4;
                this.player2.score = 0;
            }else if(player === 'player_two'){
                this.player1.score = 0;
                this.player2.score = 4;
            }


            const response = await fetch(`http://localhost:8001/api/game/result/${session}/`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                credentials: 'include',
                body: JSON.stringify({
                    winner: winner,
                    score_player_1: this.player1.score,
                    score_player_2: this.player2.score
                }),
            });
    
            if (!response.ok) {
                const errorData = await response.json();
                console.error("Failed to post game result:", errorData);
            } else {
                const result = await response.json();
                console.log("Game result successfully posted:", result);
                localStorage.removeItem('newSession');
            }
        } catch (error) {
            console.error("An error occurred while posting game result:", error);
        }
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

    collectdataToSave(winner) {
        console.log('-----------------------------------------');
        console.log('session id', localStorage.getItem('currentSessionId'));
        const newSession = localStorage.getItem('currentSessionId');
        localStorage.setItem('newSession', newSession);
        console.log('Winner is: ', winner);
        console.log('Player one is: ', this.data_of_players.player_one);
        console.log('Player two is: ', this.data_of_players.player_two);
        console.log('score of player one is: ', this.player1.score);
        console.log('score of player two is: ', this.player2.score);
        console.log('-----------------------------------------');

        this.sendToStoreData(winner);
    }

    // Function to display game over message
    displayGameOverMessage(winner) {
        // Remove any existing overlays first
        const existingOverlay = document.querySelector('.game-over-overlay');
        if (existingOverlay) {
            existingOverlay.remove();
        }

        // Create main overlay div
        const overlay = document.createElement('div');
        overlay.className = 'game-over-overlay';
        
        // Styling for the overlay
        Object.assign(overlay.style, {
            position: 'fixed',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            width: '60%',
            height: '50%',
            background: 'linear-gradient(135deg, rgba(0, 0, 0, 0.8), rgba(40, 40, 40, 0.9))',
            color: '#FFD700', // Gold text color
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'center',
            alignItems: 'center',
            textAlign: 'center',
            borderRadius: '15px',
            boxShadow: '0 4px 20px rgba(0, 0, 0, 0.7)',
            fontFamily: 'Arial, sans-serif',
            zIndex: '1000',
            animation: 'fadeIn 0.5s ease-in-out'
        });

        // Create fade-in animation
        const fadeInStyleSheet = document.createElement('style');
        fadeInStyleSheet.type = 'text/css';
        fadeInStyleSheet.innerHTML = `
            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }
        `;
        document.head.appendChild(fadeInStyleSheet);

        // Create message container
        const messageDiv = document.createElement('div');
        messageDiv.className = 'game-over-message';
        Object.assign(messageDiv.style, {
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'center'
        });

        // Set innerHTML with dynamic winner and styled elements
        messageDiv.innerHTML = `
            <h2 style="font-size: 2.5rem; font-weight: bold; margin: 0;">Game Over!!</h2>
            <h1 style="font-size: 2rem; font-weight: lighter; margin: 10px 0;">${winner} wins!</h1>
            <a id="game-over-btn" href="/" style="
                display: inline-block;
                padding: 15px 30px;
                font-size: 1rem;
                margin-top: 20px;
                background: linear-gradient(90deg, #FF4500, #FF6347);
                color: white;
                text-decoration: none;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                transition: background 0.3s, transform 0.2s;
            ">Back to Home</a>
        `;

        // Create hover effect for the button
        const buttonHoverStyle = document.createElement('style');
        buttonHoverStyle.type = 'text/css';
        buttonHoverStyle.innerHTML = `
            #game-over-btn:hover {
                background: linear-gradient(90deg, #FF6347, #FF4500);
                transform: scale(1.05);
            }
        `;
        document.head.appendChild(buttonHoverStyle);

        // Add event listener to handle navigation
        const homeButton = messageDiv.querySelector('#game-over-btn');
        homeButton.addEventListener('click', (e) => {
            e.preventDefault(); // Prevent default link behavior
            
            // Remove the overlay
            overlay.remove();
            
            // Remove the added style elements
            fadeInStyleSheet.remove();
            buttonHoverStyle.remove();
            
            // Navigate to home page
            navigate('/');
        });

        // Append message to overlay and overlay to body
        overlay.appendChild(messageDiv);
        document.body.appendChild(overlay);

        // Optional: Add a way to close the overlay by clicking outside
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                overlay.remove();
                fadeInStyleSheet.remove();
                buttonHoverStyle.remove();
            }
        });
    }

    displayGameOverMessageDis(winner) {
         // Remove any existing overlays first
         const existingOverlay = document.querySelector('.game-over-overlay');
         if (existingOverlay) {
             existingOverlay.remove();
         }
 
         // Create main overlay div
         const overlay = document.createElement('div');
         overlay.className = 'game-over-overlay';
         
         // Styling for the overlay
         Object.assign(overlay.style, {
             position: 'fixed',
             top: '50%',
             left: '50%',
             transform: 'translate(-50%, -50%)',
             width: '60%',
             height: '50%',
             background: 'linear-gradient(135deg, rgba(0, 0, 0, 0.8), rgba(40, 40, 40, 0.9))',
             color: '#FFD700', // Gold text color
             display: 'flex',
             flexDirection: 'column',
             justifyContent: 'center',
             alignItems: 'center',
             textAlign: 'center',
             borderRadius: '15px',
             boxShadow: '0 4px 20px rgba(0, 0, 0, 0.7)',
             fontFamily: 'Arial, sans-serif',
             zIndex: '1000',
             animation: 'fadeIn 0.5s ease-in-out'
         });
 
         // Create fade-in animation
         const fadeInStyleSheet = document.createElement('style');
         fadeInStyleSheet.type = 'text/css';
         fadeInStyleSheet.innerHTML = `
             @keyframes fadeIn {
                 from { opacity: 0; }
                 to { opacity: 1; }
             }
         `;
         document.head.appendChild(fadeInStyleSheet);
 
         // Create message container
         const messageDiv = document.createElement('div');
         messageDiv.className = 'game-over-message';
         Object.assign(messageDiv.style, {
             display: 'flex',
             flexDirection: 'column',
             justifyContent: 'center'
         });
 
         // Set innerHTML with dynamic winner and styled elements
         messageDiv.innerHTML = `
             <h2 style="font-size: 2.5rem; font-weight: bold; margin: 0;">Your Opponent disconnect</h2>
             <h1 style="font-size: 2rem; font-weight: lighter; margin: 10px 0;">You win!!!</h1>
             <a id="game-over-btn" href="/" style="
                 display: inline-block;
                 padding: 15px 30px;
                 font-size: 1rem;
                 margin-top: 20px;
                 background: linear-gradient(90deg, #FF4500, #FF6347);
                 color: white;
                 text-decoration: none;
                 border: none;
                 border-radius: 8px;
                 cursor: pointer;
                 transition: background 0.3s, transform 0.2s;
             ">Back to Home</a>
         `;
 
         // Create hover effect for the button
         const buttonHoverStyle = document.createElement('style');
         buttonHoverStyle.type = 'text/css';
         buttonHoverStyle.innerHTML = `
             #game-over-btn:hover {
                 background: linear-gradient(90deg, #FF6347, #FF4500);
                 transform: scale(1.05);
             }
         `;
         document.head.appendChild(buttonHoverStyle);
 
         // Add event listener to handle navigation
         const homeButton = messageDiv.querySelector('#game-over-btn');
         homeButton.addEventListener('click', (e) => {
             e.preventDefault(); // Prevent default link behavior
             
             // Remove the overlay
             overlay.remove();
             
             // Remove the added style elements
             fadeInStyleSheet.remove();
             buttonHoverStyle.remove();
             
             // Navigate to home page
             navigate('/');
         });
 
         // Append message to overlay and overlay to body
         overlay.appendChild(messageDiv);
         document.body.appendChild(overlay);
 
         // Optional: Add a way to close the overlay by clicking outside
         overlay.addEventListener('click', (e) => {
             if (e.target === overlay) {
                 overlay.remove();
                 fadeInStyleSheet.remove();
                 buttonHoverStyle.remove();
             }
         });
    }


    
    resetBall(randomSeed = null) {
        this.ball.x = this.gameCanvas.width / 2;
        this.ball.y = this.gameCanvas.height / 2;
        
        // Always use server-provided seed
        if (randomSeed !== null) {
            // Use seed to determine ball direction
            this.ball.velocityX = (randomSeed > 0.5 ? 3 : -3);
            this.ball.velocityY = (randomSeed > 0.5 ? 3 : -3);
        } else {
            // If no seed (initial reset), request from server
            this.ws.send(JSON.stringify({
                action: "request_ball_reset"
            }));
        }
    }

    setupGameEnvironment() {
        this.gameCanvas = document.querySelector("#pong");
        this.ctx = this.gameCanvas.getContext("2d");
    
        // Game Variables
        const PLAYER_WIDTH = 10, PLAYER_HEIGHT = 100, BALL_RADIUS = 10;
        this.player1 = { x: 0, y: this.gameCanvas.height / 2 - PLAYER_HEIGHT / 2, width: PLAYER_WIDTH, height: PLAYER_HEIGHT, color: 'white', score: 0 };
        this.player2 = { x: this.gameCanvas.width - PLAYER_WIDTH, y: this.gameCanvas.height / 2 - PLAYER_HEIGHT / 2, width: PLAYER_WIDTH, height: PLAYER_HEIGHT, color: 'white', score: 0 };
        
        // Initialize ball with slower speed
        this.ball = { 
            x: this.gameCanvas.width / 2, 
            y: this.gameCanvas.height / 2, 
            radius: BALL_RADIUS, 
            velocityX: 3,  // Reduced horizontal velocity
            velocityY: 3,  // Reduced vertical velocity
            color: 'white' 
        };
    
        this.initializeWebSocket();
        this.gameLoop();  // Start the game loop
    }
    
    

    initializeWebSocket() {
        if (!this.data_of_players) {
            console.error("Cannot initialize WebSocket: data_of_players is null.");
            return;
        }
    
        const sessionId = localStorage.getItem("currentSessionId");
    
        window.addEventListener('beforeunload', () => {
            localStorage.setItem('gameDisconnectionInfo', JSON.stringify({
                sessionId: sessionId,
                players: {
                    player_one: this.data_of_players.player_one,
                    player_two: this.data_of_players.player_two
                },
                currentPlayer: this.currentPlayer
            }));
        });
    
        this.ws = new WebSocket(`ws://localhost:8001/ws/game/${sessionId}/${this.data_of_players.player_one}/${this.data_of_players.player_two}/`);
    
        this.ws.onopen = () => {
            console.log('Connected to WebSocket');
            this.ws.send(JSON.stringify({
                action: "initial_state",
                player: this.currentPlayer,
                paddle_y: this.currentPlayer === 'player_one' ? this.player1.y : this.player2.y
            }));
        };
    
        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
    
            if (this.gameOver) return;
    
            switch (data.action) {
                case "ball_reset":
                    this.resetBall(data.seed);
                    break;
    
                case "score_update":
                    this.player1.score = data.player1_score;
                    this.player2.score = data.player2_score;
                    this.render();
                    this.checkGameOver();
                    break;
    
                case "game_over_disconnect":
                    this.gameOver = true;
                    console.log('--------------------------------------');
                    console.log('Game Over due to disconnection:', data);
                    console.log('currenst_session ', localStorage.getItem('currentSessionId'));
                    const session = localStorage.getItem('currentSessionId');
                    this.collectdataToSaveWhenDisconnect(data.winner , session);
                    console.log('--------------------------------------');
                    localStorage.removeItem('gameDisconnectionInfo');
                    localStorage.removeItem("currentSessionId");
                    this.displayGameOverMessageDis(data.winner);
    
                    
                    break;
    
                case "game_over":
                    this.gameOver = true;
                    console.log('Game Over:', data);
                    localStorage.removeItem("currentSessionId");
                    this.displayGameOverMessage(data.winner);
                    break;
    
                case "update":
                    if (data.data.player === "player_one" && this.currentPlayer !== "player_one") {
                        this.player1.y = data.data.paddle_y;
                    }
                    if (data.data.player === "player_two" && this.currentPlayer !== "player_two") {
                        this.player2.y = data.data.paddle_y;
                    }
    
                    if (data.data.ball) {
                        Object.assign(this.ball, data.data.ball);
                    }
    
                    this.render();
                    break;
            }
        };
    
        this.setupControls();
        this.render();
    }
    

    collectdataToSaveWhenDisconnect(winner, session) {
        const username = localStorage.getItem('my-username');
        if (winner === this.data_of_players.player_one) {
           console.log('Player one is winner');
           this.sendToStoreDataDis(username , 'player_one', session);
        }
        if (winner === this.data_of_players.player_two) {
            console.log('Player two is winner');
            this.sendToStoreDataDis(username , 'player_two', session);
        }
    }


    render() {
        this.ctx.clearRect(0, 0, this.gameCanvas.width, this.gameCanvas.height);
    
        // Draw paddles
        this.ctx.fillStyle = this.player1.color;
        this.ctx.fillRect(this.player1.x, this.player1.y, this.player1.width, this.player1.height);
    
        this.ctx.fillStyle = this.player2.color;
        this.ctx.fillRect(this.player2.x, this.player2.y, this.player2.width, this.player2.height);
    
        // Draw ball
        this.ctx.fillStyle = this.ball.color;
        this.ctx.beginPath();
        this.ctx.arc(this.ball.x, this.ball.y, this.ball.radius, 0, Math.PI * 2);
        this.ctx.fill();
    
        // Draw scores
        this.ctx.fillStyle = "white";
        this.ctx.font = "30px Arial";
        this.ctx.fillText(this.player1.score, this.gameCanvas.width / 4, 30);
        this.ctx.fillText(this.player2.score, (3 * this.gameCanvas.width) / 4, 30);
    }
    

    setupControls() {
        this.gameCanvas.addEventListener('mousemove', (event) => {
            // Get the canvas bounding rectangle
            const canvasRect = this.gameCanvas.getBoundingClientRect();
    
            // Calculate the mouse position relative to the canvas
            const mouseY = event.clientY - canvasRect.top;
    
            let paddleMove = false;
            let newY = 0;
    
            if (this.currentPlayer === 'player_one') {
                // Move player one's paddle
                newY = Math.min(Math.max(mouseY - this.player1.height / 2, 0), this.gameCanvas.height - this.player1.height);
                if (this.player1.y !== newY) {
                    this.player1.y = newY;
                    paddleMove = true;
                }
            } else if (this.currentPlayer === 'player_two') {
                // Move player two's paddle
                newY = Math.min(Math.max(mouseY - this.player2.height / 2, 0), this.gameCanvas.height - this.player2.height);
                if (this.player2.y !== newY) {
                    this.player2.y = newY;
                    paddleMove = true;
                }
            }
    
            if (paddleMove) {
                this.ws.send(JSON.stringify({
                    action: "paddle_move",
                    player: this.currentPlayer,  // Ensure the correct player identifier
                    paddle_y: newY
                }));
                this.render();  // Re-render game state after paddle move
            }
        });
    }
    
}
