import Abstract from './Abstract.js';

function loadCSS(url) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = url;
    document.head.appendChild(link);
}

export default class Home extends Abstract {
    constructor(params) {
        super(params);
        this.setTitle("Home");
        loadCSS('../styles/home.css');
    }

    async getHtml() {
        return `
            <div class="container">
                <div class="overlay">
                </div>
                <div class="mini-container">
                    <ul class="list">
                        <li class="big-li" id="active"><a href="">PLAY With Bot</a></li>
                        <li class="big-li"><a href="">Search</a></li>
                        <li class="big-li"><a href="/chat">CHAT</a></li>
                        <li class="big-li"><a href="">SETTINGS</a></li>
                        <li class="big-li"><a href="/">LOGOUT</a></li>
                    </ul>
                </div>
                <div class="mini-container-2">
                        <div class="upper"></div>
                        <div class="lower">
                            <a href="/profile">WBOUWACH</a>
                        </div>
                </div>
            </div>
        `;
    }

    initialize() {
        // Any additional initialization code
    }
}
