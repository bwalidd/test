// file: front/views/Abstract.js
export default class Abstract {
    constructor(params) {
        this.params = params;
    }

    setTitle(title) {
        document.title = title;
    }

    async getHtml() {
        return "";
    }

    async initialize() {
        // shared initialize logic 
    }

    cleanup() {
        // shared cleanup logic (to be overridden in subclasses if needed)
    }   

    redirect(path) {
        window.location = path;
    }
}
