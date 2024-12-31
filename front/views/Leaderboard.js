import Abstract from './Abstract.js';

function loadCSS(url) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = url;
    document.head.appendChild(link);
}

export default class Leaderboard extends Abstract {
    constructor(params) {
        super(params);
        loadCSS('../styles/leaderboard.css');
        this.setTitle("Leaderboard");
        this.cssSelector = '../styles/leaderboard.css';
    }

    async getHtml() {
        return `

        <div class="first-container">
            <div class="content">
                <nav class="navbar navbar-expand-lg " style="height:100px;">
                    <div class="navbar-nav">
                        <a class="nav-link" href="#">
                            <div class="notif"></div>
                        </a>
                        <a class="nav-link" href="#">
                            <div class="search"></div>
                        </a>
                        <a class="nav-link" href="#">
                            <div class="profile-img"></div>
                        </a>
                    </div>
                </nav>

                <div class="container-fluid bodypage">
                    <div class="sidebar">
                        <div class="sidebar-logo"></div>
                        <ul class="sidebar-menu">
                            <li>
                                <a href="/">
                                    <img src="../images/sidenav-img/home.png" class="sidebar-icon">
                                    <p>Home</p>
                                </a>
                            </li>
                            <li>
                                <a href="/leaderboard">
                                    <img src="../images/sidenav-img/leaderboard.png" class="sidebar-icon">
                                    <p>Leaderboard</p>
                                </a>
                            </li>
                            <li>
                                <a href="/tournaments">
                                    <img src="../images/sidenav-img/trophy.png" class="sidebar-icon">
                                    <p>Tournaments</p>
                                </a>
                            </li>
                            <li>
                                <a href="/chat">
                                    <img src="../images/sidenav-img/messages.png" class="sidebar-icon">
                                    <p>Messages</p>
                                </a>
                            </li>
                            <li>
                                <a href="/settings">
                                    <img src="../images/sidenav-img/settings.png" class="sidebar-icon">
                                    <p>Settings</p>
                                </a>
                            </li>
                        </ul>
                        <div class="sidebar-separator"></div>
                        <ul class="sidebar-menu">
                            <li>
                                <a id="logout-link">
                                    <img src="../images/sidenav-img/logout.png" class="sidebar-icon">
                                    <p>Logout</p>
                                </a>
                            </li>
                        </ul>
                 </div>



                    <div class="container leader d-flex flex-column " style="width:70%; height: 90vh">
                        <table>
                            <thead>
                                <h1>Leaderboard</h1>
                                <tr>
                                    <th class="rank">Rank</th>
                                    <th class="name">Name</th>
                                    <th class="score">Score</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${this.generateRows()}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        <script>
            document.addEventListener('scroll', function() {
                const rows = document.querySelectorAll('tbody tr');
                const tableHeader = document.querySelector('thead');

                const headerRect = tableHeader.getBoundingClientRect();
                const threshold = 10; // Adjust this value as needed

                rows.forEach(row => {
                    const rowRect = row.getBoundingClientRect();

                    if (rowRect.top <= headerRect.bottom - threshold) {
                        row.style.display = 'none'; // Remove the row
                    } else {
                        row.style.display = ''; // Reset the row's display property
                    }
                });
            });
        </script>
        `;
    }

    generateRows() {
        const rows = [];
        const players = [
            { rank: 1, name: "Alice", score: 1500 },
            { rank: 2, name: "Bob", score: 1400 },
            { rank: 3, name: "wbouuuuuwach", score: 1300 },
            { rank: 3, name: "Charlie", score: 1300 },
            { rank: 3, name: "Charlie", score: 1300 },
            { rank: 3, name: "Charlie", score: 1300 },
            { rank: 3, name: "Charlie", score: 1300 },
            { rank: 3, name: "Charlie", score: 1300 },
            { rank: 3, name: "Charlie", score: 1300 },
            { rank: 3, name: "Charlie", score: 1300 },
            { rank: 3, name: "Charlie", score: 1300 },
            { rank: 3, name: "Charlie", score: 1300 },
        ];

        players.forEach(player => {
            rows.push(`
                <tr>
                    <td class="rank">${player.rank}</td>
                    <td class="name d-flex align-items-center gap-2">
                        <div class="profile-img m-2"></div>
                        ${player.name}
                    </td>
                    <td class="score">${player.score}</td>
                </tr>
            `);
        });

        return rows.join('');
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

    initialize() {
        
    }
}