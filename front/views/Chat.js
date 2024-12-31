import { navigate } from '../index.js';
import Abstract from './Abstract.js';

function loadCSS(url) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = url;
    document.head.appendChild(link);
}

export default class Chat extends Abstract {
    constructor(params) {
        loadCSS('../styles/chat.css');
        super(params);
        this.setTitle("Chat");
        this.socket = null; // This will hold the current socket
        this.currentFriend = null; // Store the currently selected friend
        this.userData = null;
        this.cssSelector = '../styles/chat.css';
    }

    async getHtml() {
        return `
            <div class="containerr">
                <div class="overlay"></div>
                <div class="container-fluid body-content">
                    <div class="side-nav">
                        <div class="logo"></div>
                        <ul>
                            <li><a href="/"><img src="../images/sidenav-img/home.png" class="home"><p>Home</p></a></li>
                            <li><a href="/tournaments"><img src="../images/sidenav-img/trophy.png" class="home"><p>Tournaments</p></a></li>
                            <li><a href="/chat"><img src="../images/sidenav-img/messages.png" class="home"><p>Chat</p></a></li>
                            <li id="settings-part"><a href="/settings"><img src="../images/sidenav-img/settings.png" class="home"><p>Settings</p></a></li>
                        </ul>
                        <div class="sep"></div>
                        <ul>
                            <li><a id="logout-link"><img src="../images/sidenav-img/logout.png"><p>Logout</p></a></li>
                        </ul>
                    </div>

                    <div class="chat-container">
                        <div class="leftSide">
                            <div class="headerr">
                                <nav>
                                    <ul class="nav-list">
                                        <li class="nav-item"><button id="friendsTab" class="active">Friends</button></li>
                                    </ul>
                                </nav>
                            </div>
                            <div class="content">
                                <div id="friendsContent" class="tab-content active">
                                    <div class="friend-l"></div>
                                </div>
                            </div>
                        </div>
                        <div class="rightSide">
                            <h2 id="click-chat-message" style="display:none;">Select Friend To Chat With !!</h2>
                            
                            <div class="header d-flex align-items-center justify-content-between">
                                <div class="opened-chat-usename-profile" style="background: url(../images/bhazzout.jpeg); background-position: center; background-size: cover;"></div>
                                <div class="button-wrapper">

                                        <button class="game-button" id="gameButton" style="display : none;">
                                            <div class="game-ico"></div>
                                        </button>
                                        <button class="chat-enabled" id="chatEnabled" style="display:none;">
                                            <div class="chat-ico"></div>
                                        </button>
                                        <button class="chat-blocked" id="chatBlocked" style="display:none;">
                                            <div class="block-ico"></div>
                                        </button>
                                        <button class="chat-blocked-by-friend" id="chatBlockedByFriend" style="display:none;">
                                            <div class="block-by-friend-ico"></div>
                                        </button>

                                </div>
                                <div class="opened-chat-username d-flex flex-column justify-content-center" style="position:absolute; left:80px;"><h4>Wbouwach</h4></div>
                                <div class="online d-flex align-items-center" style="position:absolute; right:0; margin:5px; gap:5px"><div class="circle m-1"></div><b>Offline</b></div>
                            </div>

                            <div class="chat-box" id="chatBox">
                                <!-- Messages will be appended here -->
                            </div>

                            <div class="message-input">
                                <input type="text" id="messageInput" placeholder="Type a message..." disabled>
                                <button id="sendMsgBtn" class="send-msg-btn" disabled>Send</button>
                            </div>
                        
                        </div>
                    </div>
                </div>
            </div>

            <!-- User Info Popup -->
            <div id="user-info-popup" class="user-info-popup-chat hidden">
                <div class="user-info-content">
                    <span id="popup-close" class="popup-close">&times;</span>
                    <div class="user-card">
                        <div class="user-avatar" id="popup-avatar"></div>
                        <h2 id="popup-username"></h2>
                    </div>
                    <div class="user-actions">
                        <!-- Friend button will be inserted here --> 
                    </div>
                </div>
                <h2 class="popup-title">Stats</h2>
                <div class="user-stats">
                    <div class="stat">
                        <h3>Wins</h3>
                        <p id="number-of-match-wins">10</p>
                    </div>
                    <div class="stat">
                        <h3>Losses</h3>
                        <p id="number-of-match-losses">5</p>
                    </div>
                    <div class="stat">
                        <h3>Win Rate</h3>
                        <p id="win-rate">66%</p>
                    </div>
                </div>
                <h2 class="popup-title">Latest Matches</h2>
                <div class="latest-matches">
                    <h2 class="no-match">No Matche Played</h2>
                    <div class="match" id="matches-card">
                        <ul id="all-match-cards">
                            <li>
                                <div class="match-avatar"></div>
                                <p class="match-username">User123</p>
                                <p class="match-result">2-0</p>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        `;

    }

    async checkIsIntraUser() {
        try {
            const csrfToken = await this.getCsrfToken();
            const response = await fetch('http://localhost:8001/api/auth/user/', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`, // Ensure the token is passed
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                credentials: 'include'
            });
            const data = await response.json();
            if (data.isIntraUser === true) {
                document.getElementById('settings-part').style.display = 'none';
            }else{
                document.getElementById('settings-part').style.display = 'block';
            }
        }catch(error){
            console.error('Error checking if user is intra:', error);
        }
    }

    
    async showUserPopup(userId) {
        
        try {
            // Fetch the user's profile information from the backend
            const response = await fetch(`http://localhost:8001/api/auth/user/${userId}/`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`, // Ensure the token is passed
                    'Content-Type': 'application/json'
                }
            });
    
            if (!response.ok) {
                console.error('Error fetching user profile:', await response.text());
                return;
            }

            const user = await response.json(); // Get user data including friend status
    
            const popup = document.getElementById('user-info-popup');
            const avatarDiv = document.getElementById('popup-avatar');
            const username = document.getElementById('popup-username');
            const friendButtonContainer = document.querySelector('.user-actions');
            
            // Set avatar and username in popup
            const avatarUrl = user.isIntraUser ? user.image : `http://localhost:8001${user.avatar}`;
            avatarDiv.style.backgroundImage = `url('${avatarUrl}')`;
            avatarDiv.style.backgroundPosition = 'center';
            avatarDiv.style.backgroundSize = 'cover';
            username.textContent = user.login;
            friendButtonContainer.innerHTML = 'Already Friends';
            popup.classList.add('show'); 
    
            // Close popup when the close button is clicked
            document.getElementById('popup-close').addEventListener('click', () => {
                this.closeUserPopup();
            });
            this.collectmatchesofUser(userId);
        } catch (error) {
            console.error('Error loading user profile:', error);
        }
    }

    closeUserPopup() {
        const popup = document.getElementById('user-info-popup');
        popup.classList.remove('show');
    }

    async fetchOpponentPic(userId) {
        try {
            const response = await fetch(`http://localhost:8001/api/auth/user/${userId}/`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`, // Include token if required
                    'Content-Type': 'application/json'

                },
                credentials: 'include'
            }
            );
            const res = await response.json();
            return res;
        }catch (error) {
            console.error('Error fetching opponent pic:', error);

        }
    }
    
    async collectmatchesofUser(userId) {
        try {
            const response = await fetch(`http://localhost:8001/api/game/allmygames/${userId}/`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`, // Include token if required
                    'Content-Type': 'application/json'
                },
            });
            const data = await response.json();
            // console.log('Data length:', data.length);

            const matchesCard = document.getElementById('matches-card');
            if (!matchesCard) {
                console.error('Matches card element not found in the DOM.');
                return;
            }
            console.log('matches played ==>', data.length, '===> ', userId);
            if (data.length === 0) {
                document.querySelector('.no-match').style.display = 'block';
                document.querySelector('.no-match').style.marginTop = '120px';
                document.querySelector('.no-match').style.textAlign = 'center';
                document.getElementById('matches-card').style.display = 'none';
                document.getElementById('win-rate').textContent = '0%';
                document.getElementById('number-of-match-wins').textContent = '0';
                document.getElementById('number-of-match-losses').textContent = '0';
            } else {
                document.querySelector('.no-match').style.display = 'none';
                document.getElementById('matches-card').style.display = 'block';
                document.getElementById('number-of-match-wins').textContent = '10';
                document.getElementById('number-of-match-losses').textContent = '5';
    
                const allMatchCards = document.getElementById('all-match-cards');
                allMatchCards.innerHTML = '';
                let winningmatches = 0;
                let losingmatches = 0;
                let totalMatches = 0;
    
                for (let i = 0; i < data.length; i++) {
                    const match = data[i];
                    
                    let dataofOpponent;
    
                    if (userId === match.player_one) {
                        // console.log('match ', i, ' i am Player one');
                        dataofOpponent = await this.fetchOpponentPic(match.player_two);
                        // console.log('Opponent data: of player two', dataofOpponent);
                    } else {
                        // console.log('match ', i, ' i am Player two');
                        dataofOpponent = await this.fetchOpponentPic(match.player_one);
                        // console.log('Opponent data: of player one', dataofOpponent);
                    }
    
                    const matchCard = document.createElement('li');
                    const matchAvatar = document.createElement('div');
                    matchAvatar.className = 'match-avatar';
    
                    const matchUsername = document.createElement('p');
                    matchUsername.className = 'match-username';
                    const avatarUrl = dataofOpponent.isIntraUser ? dataofOpponent.image : `http://localhost:8001${dataofOpponent.avatar}`;
                    matchAvatar.style.backgroundImage = `url('${avatarUrl}')`;
                    matchUsername.textContent = dataofOpponent.login;
    
                    const matchResult = document.createElement('p');
                    matchResult.className = 'match-result';
                    matchResult.textContent = `${match.score_player_1}  -  ${match.score_player_2}`;
    
                    matchCard.appendChild(matchAvatar);
                    matchCard.appendChild(matchUsername);
                    matchCard.appendChild(matchResult);
                    allMatchCards.appendChild(matchCard);
                    if ((userId === match.player_one && match.score_player_1 > match.score_player_2) ||
                        (userId === match.player_two && match.score_player_2 > match.score_player_1)) {
                        matchCard.style.border   = '2px solid green';
                        winningmatches++;
                        totalMatches++;
                    }else{
                        matchCard.style.border   = '2px solid red';
                        losingmatches++;
                        totalMatches++;
                    }
                }
                document.getElementById('number-of-match-wins').textContent = winningmatches;
                document.getElementById('number-of-match-losses').textContent = losingmatches;
                const winRate = (winningmatches / (winningmatches + losingmatches)) * 100;
                document.getElementById('win-rate').textContent = `${winRate.toFixed(2)}%`;
            }
        } catch (error) {
            console.error('Error fetching user matches:', error);
        }
    }

    openProfileClicked(friendId) {
        const usernameElement = document.querySelector('.opened-chat-username');
        
        // Remove any existing event listeners
        usernameElement.onclick = null;
        
        // Add a single event listener using onclick
        usernameElement.onclick = async () => {
            console.log('User clicked on the profile');
            await this.showUserPopup(friendId);
        };
    }

    connectWebSocket(friendId) {
        if (this.socket) {
            this.socket.close();
        }
    
        this.socket = new WebSocket(`ws://localhost:8001/ws/wsc/${this.userData.id}/${friendId}/`);
        this.socket.onopen = () => {
            // console.log(`WebSocket connected with friend ID ${friendId}.`);
            this.enableChatInput(true);
        };
    
        this.socket.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === 'status' && data.user_id === friendId) {
                this.updateOnlineStatus(data.status === 'online');
            } else if (data.msg) {
                this.handleIncomingMessage(data, friendId);
            }
        };
    
        this.socket.onclose = () => {
            // console.log(`WebSocket connection closed for friend ID ${friendId}.`);
            this.enableChatInput(false);
        };
    }

    enableChatInput(enable) {
        const messageInput = document.getElementById('messageInput');
        const sendMsgBtn = document.getElementById('sendMsgBtn');
    
        if (!messageInput || !sendMsgBtn) {
            return;
        }
    
        messageInput.disabled = !enable;
        sendMsgBtn.disabled = !enable;
    }
    
    
    
    async fetchUserIds(userID , dest){
        const csrfToken = await this.getCsrfToken();
        const response = await fetch(`http://localhost:8001/api/auth/user/${userID}/`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('access_token')}`, // Ensure the token is passed
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            credentials: 'include'
        });

        if (!response.ok) {
            console.error('Error fetching user profile:', await response.text());
            return;
        }
        const data = await response.json();
        dest = data.login;
    }

    async fetchUsername(userId) {
        const csrfToken = await this.getCsrfToken();
        try {
            const response = await fetch(`http://localhost:8001/api/auth/user/${userId}/`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                credentials: 'include'
            });
    
            if (!response.ok) {
                console.error(`Error fetching username for user ID ${userId}:`, await response.text());
                return null;
            }
    
            const data = await response.json();
            return data.login;
        } catch (error) {
            console.error('Error in fetchUsername:', error);
            return null;
        }
    }
    

 
    async saveMatchData(data) {
        console.log("Match data:", data);
        const csrfToken = await this.getCsrfToken();
    
        try {
            const response = await fetch('http://localhost:8001/api/game/start/', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                credentials: 'include',
                body: JSON.stringify({
                    player_one: data.to, // Inviter's ID
                    player_two: data.from,   // Invitee's ID
                    session_id: data.session_id // Session ID from the WebSocket message
                }),
            });
    
            // if (!response.ok) {
            //     console.error('Error starting the game:', await response.text());
            //     return;
            // }
    
            const responseData = await response.json();
            console.log("Game session created:", responseData);
    
        } catch (error) {
            console.error('Error in saveMatchData:', error);
        }
    }
        
    connectGameInviteSocket(friendId) {
        const userId = this.userData.id;
        const userName = this.userData.login; // Get the current user's name
    
        // Close any existing socket
        if (this.gameSocket) {
            this.gameSocket.close();
        }
    
        // Establish a new WebSocket connection
        this.gameSocket = new WebSocket(`ws://localhost:8001/ws/game-invite/${userId}/${friendId}/`);
    
        this.gameSocket.onopen = () => {
            // console.log(`Game WebSocket connected for friend ID: ${friendId}`);
        };
    
        this.gameSocket.onmessage = (event) => {
            const data = JSON.parse(event.data);
    
            // Handle game invitation message
            if (data.type === "game_invitation") {
                const alertBox = document.createElement("div");
                alertBox.className = "invite-alert";
                console.log("data from invite", data);
                alertBox.innerHTML = `
                    <p>${data.message}</p>
                    <div class="alert-buttons">
                        <button class="accept-btn">Accept</button>
                        <button class="decline-btn">Decline</button>
                    </div>
                `;
                document.body.appendChild(alertBox);
    
                const acceptButton = alertBox.querySelector(".accept-btn");
                const declineButton = alertBox.querySelector(".decline-btn");
    
                acceptButton.addEventListener("click", () => {
                    // Send game response with player names and session ID
                    this.gameSocket.send(
                        JSON.stringify({
                            type: "game_response",
                            from: this.userData.id,
                            to: data.from,
                            response: "accepted",
                            session_id: data.session_id,
                            player1_name: userName, // Include the current user's name
                            player2_name: data.from_name, // Include the inviter's name
                        })
                    );
                    alertBox.remove();
                });
    
                declineButton.addEventListener("click", () => {
                    // Handle game decline logic
                    this.gameSocket.send(
                        JSON.stringify({
                            type: "game_response",
                            from: this.userData.id,
                            to: data.from,
                            response: "declined",
                        })
                    );
                    alertBox.remove();
                });
    
                setTimeout(() => {
                    if (alertBox) {
                        alertBox.remove();
                    }
                }, 4000);
            }
    
            else if (data.type === "game_response") {
                console.log(`Game response from ${data.from}: ${data.response}`);
                if (data.response === "accepted") {
                    alert("Game Accepted!");
                } else if (data.response === "declined") {
                    alert("Game Declined!");
                }
            }
    
            else if (data.type === "navigate_to_play") {
                const sessionId = data.session_id; // Extract the session ID
                console.log("Navigating to /play with session ID:", sessionId);

                // Option 2: Store sessionId in localStorage (optional for simplicity)
                localStorage.setItem("currentSessionId", sessionId);

                if (data.from === this.userData.id) {
                    console.log("User is the inviter. Saving match data...");
                    this.saveMatchData(data);
                }
                navigate('/play');
            } else {
                console.log("Unhandled WebSocket message:", data);
            }
        };
    
        this.gameSocket.onclose = () => {
            // console.log("Game WebSocket connection closed.");
        };
    
        this.gameSocket.onerror = (error) => {
            console.error("Game WebSocket error:", error);
        };
    }
    

    updateOnlineStatus(isOnline) {
        const onlineIndicator = document.querySelector('.online b');
        const statusCircle = document.querySelector('.online .circle');
    
        if (!onlineIndicator || !statusCircle) {
            return;
        }
    
        if (isOnline) {
            onlineIndicator.textContent = 'Online';
            statusCircle.style.backgroundColor = 'green';
        } else {
            onlineIndicator.textContent = 'Offline';
            statusCircle.style.backgroundColor = 'gray';
        }
    }
    

    handleIncomingMessage(data, friendId) {
        const { msg, sender } = data; // Ensure 'sender' and 'msg' are included in the message data
        const chatBox = document.getElementById('chatBox');
        chatBox.innerHTML += `<div class="message received"><div class="message-content">${msg}</div></div>`;
        chatBox.scrollTop = chatBox.scrollHeight; // Scroll to the bottom
    
        // Trigger the notification
        console.log('sender message:------->', friendId,"message---->", msg);
        this.showNotification({ sender, msg },friendId);
    }

    

    async showNotification(message,friendId) {
        // console.log("hi from notification");
        const csrfToken = await this.getCsrfToken();
        try {
            const response = await fetch(`http://localhost:8001/api/auth/user/${friendId}`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                }
            });
            if (!response.ok) throw new Error(`Failed to fetch user data: ${response.statusText}`);
    
            const userData = await response.json();
            const notification = document.createElement('div');
            notification.classList.add('notification');
            notification.innerHTML = `
                <div class="notification-content">
                    <strong>${userData.login}</strong>: ${message.msg.length <= 15 ? message.msg : message.msg.slice(0, 15) + '...'}
                </div>
            `;
            document.body.appendChild(notification);
    
            setTimeout(() => notification.classList.add('show'), 10);
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => notification.remove(), 3000);
            }, 3000);
        } catch (error) {
            console.error('Notification error:', error);
        }
    }
    
    sendMessages() {
        const sendMsgBtn = document.getElementById('sendMsgBtn');
        sendMsgBtn.addEventListener('click', () => {
            const messageInput = document.getElementById('messageInput');
            const message = messageInput.value.trim();
    
            if (message && this.socket) {
                this.socket.send(JSON.stringify({ msg: message }));
                const chatBox = document.getElementById('chatBox');
                chatBox.innerHTML += `<div class="message sent"><div class="message-content">${message}</div></div>`;
                messageInput.value = ''; // Clear the input field
                chatBox.scrollTop = chatBox.scrollHeight; // Scroll to the bottom
            } else {
                alert('Please enter a message or connect to a friend.');
            }
        });
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

    async fetchUserData() {
        try {
            const csrfToken = await this.getCsrfToken();
            const response = await fetch('http://localhost:8001/api/auth/user/', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                }
            });

            if (!response.ok) {
                const errorDetails = await response.text();
                throw new Error(`Failed to fetch user data: ${response.status} ${response.statusText} - ${errorDetails}`);
            }

            this.userData = await response.json();
            // console.log('User data:', this.userData);
            this.populateFriends(this.userData.friends);
        } catch (error) {
            console.error('Error fetching user data:', error);
        }
    }

    async populateFriends(friends) {
        const friendsList = document.querySelector('.friend-l');
        friendsList.innerHTML = ''; // Clear any existing content

        if (friends.length === 0) {
            friendsList.innerHTML = '<p>No friends found.</p>'; // Message if no friends
            return;
        }

        friends.forEach(friend => {
            const friendBlock = document.createElement('div');
            friendBlock.classList.add('friend-block');
            console.log('Friend:--->', friend);
            const friendImage = friend.isIntraUser ? friend.image : `http://localhost:8001${friend.avatar}`;
            console.log('Friend image:', friendImage);
            friendBlock.innerHTML = `
                <div class="cover" style="background: url(${friendImage}); background-position: center; background-size: cover;"></div>
                <div class="details d-flex justify-content-between">
                    <div class="listHead">
                        <h5>${friend.login}</h5>
                    </div>
                </div>
            `;

            friendBlock.addEventListener('click', () => {
                this.displaySelectedFriend(friend);
            });

            friendsList.appendChild(friendBlock);
        });
    }

    async displaySelectedFriend(friend) {
        // console.log('Selected friend:', friend);
        this.initChat('clicked');
        const username = document.querySelector('.opened-chat-username h4');
        username.textContent = friend.login;
        const friendImage = friend.isIntraUser ? friend.image : `http://localhost:8001${friend.avatar}`;
        const profile = document.querySelector('.opened-chat-usename-profile');
        profile.style.background = `url(${friendImage})`;
        profile.style.backgroundPosition = 'center';
        profile.style.backgroundSize = 'cover';
    
        // Clear the chat box when switching friends
        const chatBox = document.getElementById('chatBox');
        chatBox.innerHTML = ''; // Clear previous messages
    
        this.currentFriend = friend;
        await this.loadChatHistory(friend.id); // Load chat history before connecting WebSocket
        this.connectWebSocket(friend.id); // Assuming friend has an id property
        this.connectGameInviteSocket(friend.id);
        this.checkChatStatus(friend.id);
        this.openProfileClicked(friend.id);
    }

    // websocket to check if the friend blocking status
    async checkChatStatus(friendId) {
        const userId = this.userData.id;
        const ws = new WebSocket(`ws://localhost:8001/ws/chat-status/${userId}/${friendId}/`);
        ws.onopen = () => {
            // console.log(`Chat statusWebSocket connected for friend ID ${friendId}`);
        };
    
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            // console.log('Chat status:', data);
            if (data.status === 'blocked') {
                // console.log('Chat is blocked by you');
                // Disable the chat input
                document.getElementById('messageInput').disabled = true;
                document.getElementById('chatBlocked').style.display = 'none';
                document.getElementById('gameButton').style.display = 'none';
                document.getElementById('chatEnabled').style.display = 'block';
                document.getElementById('chatEnabled').style.marginLeft = '10px';

                document.addEventListener('click', (event) => {
                    if (event.target.id === 'chatEnabled') {
                        // console.log('Unblocking the chat');
                        this.UnBlockYourFriend(friendId);
                        document.getElementById('gameButton').style.display = 'block';
                    }
                    // console.log('----->Unblocking the chat');
                });
            } else if (data.status === 'blocked_by_friend') {
                // console.log('Chat is blocked by the friend');
                // Disable the chat input
                document.getElementById('messageInput').disabled = true;
                document.getElementById('chatBlocked').style.display = 'none';
                document.getElementById('chatBlockedByFriend').style.display = 'block';
                document.getElementById('gameButton').style.display = 'none';
                document.getElementById('chatBlockedByFriend').style.marginLeft = '10px';
            } else {
                // console.log('Chat is enabled');
                document.getElementById('messageInput').disabled = false;
                document.getElementById('chatBlocked').style.display = 'block';
                document.getElementById('gameButton').style.display = 'block';
                document.getElementById('chatEnabled').style.display = 'none';
                document.getElementById('chatBlockedByFriend').style.display = 'none';
                document.getElementById('chatBlocked').style.marginLeft = '10px';
                document.addEventListener('click', (event) => {
                    if (event.target.id === 'chatBlocked') {
                        
                        this.blockYourFriend(friendId);
                        document.getElementById('gameButton').style.display = 'none';
                    }
                    // console.log('----->blocking the chat');
                });
            }
        };
    
        ws.onclose = () => {
            console.log(`Chat status WebSocket closed for friend ID ${friendId}`);
        };
    
        ws.onerror = (error) => {
            console.error('Chat status WebSocket error:', error);
        };
    }

    async blockYourFriend(friendId) {
        try {
            const csrfToken = await this.getCsrfToken();
            const response = await fetch(`http://localhost:8001/api/chats/block/${this.userData.id}/${friendId}/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'X-CSRFToken': csrfToken
                },
                credentials: 'include',
                
            });
    
            if (!response.ok) {
                const errorData = await response.json();
                console.error('Failed to block friend:', errorData);
                alert('Failed to block friend. Please try again.');
                return;
            }
    
            const data = await response.json();
            console.log('Successfully blocked friend:', data);
    
            alert('Friend successfully blocked!');
            document.getElementById('messageInput').disabled = true;
            document.getElementById('chatBlocked').style.display = 'none';
            document.getElementById('chatEnabled').style.display = 'block';

        } catch (error) {
            console.error('Error blocking friend:', error);
            alert('An error occurred while blocking the friend. Please try again.');
        }
    }
    
    async UnBlockYourFriend(friendId) {
        try {
            const csrfToken = await this.getCsrfToken();
            const response = await fetch(`http://localhost:8001/api/chats/unblock/${this.userData.id}/${friendId}/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'X-CSRFToken': csrfToken
                },
                credentials: 'include',
                
            });
    
            if (!response.ok) {
                const errorData = await response.json();
                console.error('Failed to unblock friend:', errorData);
                alert('Failed to unblock friend. Please try again.');
                return;
            }
    
            const data = await response.json();
            console.log('Successfully unblocked friend:', data);
    
            alert('Friend successfully unblocked!');
            document.getElementById('messageInput').disabled = false;
            document.getElementById('chatBlocked').style.display = 'block';
            document.getElementById('chatEnabled').style.display = 'none';

        } catch (error) {
            console.error('Error unblocking friend:', error);
            alert('An error occurred while unblocking the friend. Please try again.');
        }
    }

    
    async loadChatHistory(friendId) {
        try {
            const response = await fetch(`http://localhost:8001/api/chats/messages/${this.userData.id}/${friendId}/`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'Content-Type': 'application/json'
                }
            });
    
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Failed to load chat history: ${errorText}`);
            }
    
            const data = await response.json(); // Get the complete response object
            // console.log('API Response:', data); // Log the response for debugging
    
            // Check if messages is an array within the data object
            if (!Array.isArray(data.messages)) {
                console.error('Expected messages to be an array, but got:', data.messages);
                return; // Exit the function if it's not an array
            }
    
            const chatBox = document.getElementById('chatBox');
            chatBox.innerHTML = ''; // Clear existing messages before appending new ones
    
            data.messages.forEach(msg => {
                // console.log('Message Object:', msg); // Log the individual message object for further inspection
    
                // Update the properties based on the actual structure
                const messageClass = msg.sender === this.userData.id ? 'sent' : 'received';
                const messageContent = msg.message || ''; // Use msg.message for content
    
                chatBox.innerHTML += `
                    <div class="message ${messageClass}">
                        <div class="message-content">${messageContent}</div>
                    </div>
                `;
            });
            chatBox.scrollTop = chatBox.scrollHeight; // Scroll to the bottom to show latest messages
        } catch (error) {
            console.error('Error loading chat history:', error);
        }
    }
    
    
    
    

    initialize() {
        this.inviter = null;
        this.invitee = null;
        this.checkIsIntraUser();
        document.getElementById('logout-link').addEventListener('click', async (event) => {
            event.preventDefault();
            await this.logoutUser();
            
            navigate('/welcome');
        });
    
        this.initChat('notClicked');
    
        this.fetchUserData();
        this.sendMessages(); // Make sure to call sendMessages
        this.inviteToGame();
    }

    initChat(status) {
        const headerElement = document.querySelector('.header');
        const chatBoxElement = document.querySelector('.chat-box');
        const messageInputElement = document.querySelector('.message-input');
        const clickChatMessageElement = document.getElementById('click-chat-message');
    
        if (status === 'notClicked') {
            // Add a CSS class to hide the header
            headerElement.classList.add('hidden');
    
            // Hide the chat box and message input
            chatBoxElement.style.display = 'none';
            messageInputElement.style.display = 'none';
    
            // Show the "click a Chat to Start" message
            clickChatMessageElement.style.display = 'block';
        } else if (status === 'clicked') {
            // Remove the CSS class to show the header
            headerElement.classList.remove('hidden');
    
            // Show the chat box and message input
            chatBoxElement.style.display = 'block';
            messageInputElement.style.display = 'flex';
    
            // Hide the "click a Chat to Start" message
            clickChatMessageElement.style.display = 'none';
        }
    }
    

    async inviteToGame() {
        const gameButton = document.getElementById("gameButton");
        gameButton.addEventListener("click", () => {
            if (!this.currentFriend) {
                alert("Please select a friend to invite to a game.");
                return;
            }
    
            // Send the game invitation through the WebSocket
            if (this.gameSocket && this.gameSocket.readyState === WebSocket.OPEN) {
                const invitationData = {
                    type: "game_invitation",
                    from: this.userData.id,
                    to: this.currentFriend.id,
                    message: `${this.userData.login} has invited you to a game.`,
                };
    
                this.gameSocket.send(JSON.stringify(invitationData));
                // alert(`Game invitation sent to ${this.currentFriend.username}!`);
                const alertBox = document.createElement('div');
                alertBox.className = 'custom-alert';
                alertBox.innerText = 'Game invitation sent !';
                document.body.appendChild(alertBox);
                setTimeout(() => {
                    alertBox.remove();
                }, 3000);
            } else {
                alert("Game WebSocket is not connected.");
            }
        });
    }
    

    setActiveTab(tab, content) {
        document.querySelectorAll('.nav-item button, .tab-content').forEach(el => el.classList.remove('active'));
        tab.classList.add('active');
        content.classList.add('active');
    }

    async logoutUser() {
        try {
            const csrfToken = await this.getCsrfToken();
            const accessToken = localStorage.getItem('access_token');
    
            const response = await fetch('http://localhost:8001/api/auth/logout/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {}),
                    'X-CSRFToken': csrfToken
                },
                credentials: 'include'
            });
    
            const data = await response.json();
    
            if (!response.ok) {
                throw new Error(data.detail || 'Logout failed');
            }
    
            // Clear tokens and navigate
            localStorage.removeItem('access_token');
            if (localStorage.getItem('refresh_token')) {
                localStorage.removeItem('refresh_token');
            }
            
    
         
    
            navigate('/welcome');
    
        } catch (error) {
            console.error('Error during logout:', error);
            
            // Create error alert
            const alertBox = document.createElement('div');
            alertBox.className = 'custom-alert error';
            alertBox.innerText = error.message || 'Logout failed. Please try again.';
            document.body.appendChild(alertBox);
    
            setTimeout(() => {
                alertBox.remove();
            }, 3000);
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
}
