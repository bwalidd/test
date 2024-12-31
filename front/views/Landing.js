import Abstract from './Abstract.js';

function loadCSS(url) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = url;
    document.head.appendChild(link);
}

export default class Landing extends Abstract {
    constructor(params) {
        super(params);
        this.setTitle("Landing");
        this.cssUrl = '../styles/Landing.css';
    }

    async getHtml() {
        return `

        <div class="first-container">

            <div class="blurred-overlay"></div>

            <div class="container nav-bar d-flex m-auto h-70 w-100 align-items-center justify-content-center">
                <div class="logo">
                    <img src="../images/pongx.png" alt="logoooooo" width="300px" height="200px">
                </div>
                <div class="gradient-line"></div>
            </div>


            <div class="container sign-in  h-50 d-flex justify-content-center align-items-center">
                <button class="btn btn-outline-light btn-lg centered-button w-100">LOGIN</button>
            </div>
        </div>
        `;
    }

    initialize() {
        
    }
}
