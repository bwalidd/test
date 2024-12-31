import { navigate } from '../index.js';
import Abstract from './Abstract.js';
import { fetchUserData } from './authutils.js';

function loadCSS(url) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = url;
    document.head.appendChild(link);
}

export default class Profile extends Abstract {
    constructor(params) {
        loadCSS('../styles/Profile.css');
        super(params);
        this.setTitle("Profile");
        this.cssSelector = '../styles/Profile.css';
        this.user = null;
        this.winRate = 0;
    }

    async getHtml() {
        this.user = await fetchUserData('http://localhost:8001/api/auth/user/');
        
        // console.log('Avatar URL:', avatarUrl);
    
        return `
        <div class="first-container">
            <nav class="navbar navbar-expand-lg" style="height:100px;">
                <div class="navbar-nav"></div>
            </nav>
            <div class="containerr">
                <div class="overlay"></div>
                <div class="side-nav">
                        <div class="logo"></div>
                        <ul>
                            <li>
                                <a href="/">
                                    <img src="../images/sidenav-img/home.png" class="home">
                                    <p>Home</p>
                                </a>
                            </li>
                            <li>
                                <a href="/tournaments">
                                    <img src="../images/sidenav-img/trophy.png" class="home">
                                    <p>Tournaments</p>
                                </a>
                            </li>
                            <li>
                                <a href="/chat">
                                    <img src="../images/sidenav-img/messages.png" class="home">
                                    <p>Chat</p>
                                </a>
                            </li>
                            <li id="settings-part">
                                <a href="/settings">
                                    <img src="../images/sidenav-img/settings.png" class="home">
                                    <p>Settings</p>
                                </a>
                            </li>
                        </ul>
                        <div class="sep"></div>
                        <ul>
                            <li>
                                <a id="logout-link">
                                    <img src="../images/sidenav-img/logout.png">
                                    <p>Logout</p>
                                </a>
                            </li>
                        </ul>
                    </div>   
                <div class="center-rectangle">
                    <div id="first-container">
                        <div id="right-part">
                            <div class="profile-img"></div>
                            <div class="profile-name">${this.user.login}</div>
                        </div>
                        <div id="left-part">
                            <div class="wrapper">
                                <div class="c100 red over50" style="--p:80;">
                                    <span id="win-rate-percentage">0%</span>
                                    <div class="slice">
                                        <div class="bar"></div>
                                        <div class="fill"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div id="second-container">
                        <div id="first-part">
                            <h1>Total Matches</h1>
                            <h2 id="total-match-played">0</h2> <!-- Added -->
                        </div>
                        <div id="second-part">
                            <h1>total Wins</h1>
                            <h2 id="total-match-wins">0</h2> <!-- Added -->
                        </div>
                        <div id="third-part">
                            <h1>total Losses</h1>
                            <h2 id="total-match-losses">0</h2> <!-- Added -->
                        </div>
                    </div>
                    <div id="third-container">
                        <div class="match" id="matches-card">
                            <ul id="all-match-cards">
                                <li>
                                    <div class="match-avatar"></div>
                                    <p class="match-username">User123</p>
                                    <p class="match-result">2-0</p>
                                </li>
                            </ul>
                        </div>
                        <div class="no-matches-message" style="display: none;">No matches found.</div>
                    </div>
                </div>
            </div>
        </div>
        `;
    }
    
    async loggingOut() {
        document.getElementById('logout-link').addEventListener('click', async (event) => {
            event.preventDefault();
            await this.logoutUser();
            localStorage.removeItem('access_token');
            if(localStorage.removeItem('refresh_token')){
                localStorage.removeItem('refresh_token');
            }
            navigate('/welcome');
        });
    }
    

    initialize() {
        this.checkIsIntraUser();
        this.putProfileImage();
        this.getDataofProfile(this.user.id);
        this.loggingOut();

        // this.animateWinRate(this.winRate);
    }

   /**
 * Animate the win rate percentage from 0 to the target value.
 * @param {number} targetPercentage - The final win rate percentage.
 */
animateWinRate(targetPercentage) {
    const element = document.getElementById('win-rate-percentage');
    let currentPercentage = 0;
    const duration = 4000; // 4 seconds total animation time
    const startTime = performance.now();

    const animate = (currentTime) => {
        const elapsedTime = currentTime - startTime;
        const progress = Math.min(elapsedTime / duration, 1);

        // Use an easing function for smooth acceleration and deceleration
        const easeInOutQuad = progress < 0.5 
            ? 2 * progress * progress 
            : -1 + (4 - 2 * progress) * progress;

        currentPercentage = targetPercentage * easeInOutQuad;

        element.textContent = `${currentPercentage.toFixed(1)}%`;

        if (progress < 1) {
            requestAnimationFrame(animate);
        } else {
            // Ensure we end exactly at the target percentage
            element.textContent = `${targetPercentage}%`;
        }
    };

    requestAnimationFrame(animate);
}


    putProfileImage() {
        const profileImage = document.querySelector('.profile-img');
        const avatarUrl = this.user.isIntraUser ? this.user.image : `http://localhost:8001${this.user.avatar}`;
        profileImage.style.backgroundImage = `url('${avatarUrl}')`;
    }

    async fetchOpponentPic(userId) {
        try {
            const response = await fetch(`http://localhost:8001/api/auth/user/${userId}/`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`, // Include token if required
                    'Content-Type': 'application/json'

                }}
            );
            const res = await response.json();
            return res;
        }catch (error) {
            console.error('Error fetching opponent pic:', error);

        }
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

    async getDataofProfile(userId) {
        // console.log('Fetching user matches of user:', userId);
        try {
            const response = await fetch(`http://localhost:8001/api/game/allmygames/${userId}/`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'Content-Type': 'application/json'
                },
            });
            const data = await response.json();
            
    
            const noMatchesMessage = document.querySelector('.no-matches-message');
            const matchesCard = document.getElementById('matches-card');
            const allMatchCards = document.getElementById('all-match-cards');
    
            if (data.length === 0) {
                
                noMatchesMessage.style.display = 'block';
                noMatchesMessage.style.marginTop = '120px';
                noMatchesMessage.style.textAlign = 'center';
                noMatchesMessage.style.fontSize = '40px';
                noMatchesMessage.style.fontfamily = 'Ga Maamli';
                matchesCard.style.display = 'none';
            } else {
                
                noMatchesMessage.style.display = 'none';
                matchesCard.style.display = 'block';
    
                // Clear existing match cards
                allMatchCards.innerHTML = '';
                let winningMatches = 0;
                let losingMatches = 0;
    
                for (let i = 0; i < data.length; i++) {
                    const match = data[i];
                    
    
                    let dataOfOpponent;
    
                    if (userId === match.player_one) {
                        dataOfOpponent = await this.fetchOpponentPic(match.player_two);
                    } else {
                        dataOfOpponent = await this.fetchOpponentPic(match.player_one);
                    }
    
                    const matchCard = document.createElement('li');
    
                    const matchAvatar = document.createElement('div');
                    matchAvatar.className = 'match-avatar';
                    const avatarUrl = dataOfOpponent.isIntraUser ? dataOfOpponent.image : `http://localhost:8001${dataOfOpponent.avatar}`;
                    matchAvatar.style.backgroundImage = `url('${avatarUrl}')`;
    
                    const matchUsername = document.createElement('p');
                    matchUsername.className = 'match-username';
                    matchUsername.textContent = dataOfOpponent.login;
    
                    const matchResult = document.createElement('p');
                    matchResult.className = 'match-result';
                    matchResult.textContent = `${match.score_player_1}  -  ${match.score_player_2}`;
    
                    matchCard.appendChild(matchAvatar);
                    matchCard.appendChild(matchUsername);
                    matchCard.appendChild(matchResult);
                    allMatchCards.appendChild(matchCard);
    
                    if ((userId === match.player_one && match.score_player_1 > match.score_player_2) ||
                        (userId === match.player_two && match.score_player_2 > match.score_player_1)) {
                        matchCard.style.border = '2px solid green';
                        winningMatches++;
                    } else {
                        matchCard.style.border = '2px solid red';
                        losingMatches++;
                    }
                }
                document.getElementById('total-match-played').textContent = data.length;
                document.getElementById('total-match-wins').textContent = winningMatches;
                document.getElementById('total-match-losses').textContent = losingMatches;
                this.winRate = Math.round((winningMatches / data.length) * 100);
                this.animateWinRate(this.winRate);
                // document.getElementById('win-rate-percentage').textContent = `${Math.round((winningMatches / data.length) * 100)}%`;
            }
        } catch (error) {
            console.error('Error fetching user matches:', error);
        }
    }
    


    cleanup() {
        

        // Remove the dynamically added CSS
        const cssLink = document.querySelector(`link[href="${this.cssSelector}"]`);
        if (cssLink) {
            cssLink.remove();
        }
    }

    async  getCsrfToken() {
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
            if(localStorage.removeItem('refresh_token')){
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
}
