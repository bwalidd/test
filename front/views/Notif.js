import Abstract from './Abstract.js';

// function loadCSS(url) {
//     const link = document.createElement('link');
//     link.rel = 'stylesheet';
//     link.href = url;
//     document.head.appendChild(link);
// }

export default class Home extends Abstract {
    constructor(params) {
        super(params);
        this.setTitle("Home");
        
    }

    async getHtml() {
        return `
            <div class="container">
               <button class="btn btn-danger">Sign in With Intra 42</button>
            </div>
        `;
    }

    initialize() {
        // Any additional initialization code
    }
}
