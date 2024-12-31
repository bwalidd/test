// Your existing routes and loadView function
const routes = [
    {path: "/welcome", view: "Welcome"},
    {path:"/play",view:"GameRemote"},
    {path:"/enable2fa",view:"Enable2Fa"},
    {path:"/login2fa",view:"Handle2Fa"},
    {path: "/training", view: "GameAi"},
    {path: "/friendly", view: "LocalMatch"},
    {path:"/tournaments",view:"Tournaments"},
    { path: "/", view: "Home"},
    { path: "/home", view: "Home"},
    { path: "/login", view: "Login"},
    { path: "/signup", view: "Signup"},
    { path: "/notif", view: "Notif" },
    { path: "/profile", view: "Profile" },
    { path: "/chat", view: "Chat"},
    { path: "/leaderboard", view: "Leaderboard"},
    { path: "/settings", view: "settings"},
];

const shouldAuthpages = ["Profile", "Chat", "Leaderboard","GameRemote","Settings","GameAi","LocalMatch","Tournaments"];
const tmpAuthpages = ["Handle2Fa","Enable2Fa"];
const shouldNotAuthpages = ["Login", "Signup", "Welcome"];

const loadCSS = (url) => {
    return new Promise((resolve, reject) => {
        let existingLink = document.querySelector(`link[href="${url}"]`);
        if (!existingLink) {
            const link = document.createElement('link');
            link.rel = 'stylesheet';
            link.href = url;
            link.className = 'dynamic-css';
            link.onload = () => resolve();
            link.onerror = () => reject(new Error(`Failed to load CSS: ${url}`));
            document.head.appendChild(link);
        } else {
            resolve();
        }
    });
};

const unloadCSS = () => {
    document.querySelectorAll('link.dynamic-css').forEach(link => link.remove());
};


const loadedCSS = new Set();

let currentViewInstance = null;

const loadView = async (path) => {
    const route = routes.find(route => route.path === path);
    const viewName = route ? route.view : "NotFound";

    try {
        // Call cleanup on the current view instance if it exists
        if (currentViewInstance && typeof currentViewInstance.cleanup === 'function') {
            await currentViewInstance.cleanup();
        }

        // Import the new view module
        const module = await import(`../views/${viewName}.js`);
        if (shouldAuthpages.includes(viewName) && !localStorage.getItem('access_token')) {
            alert('You need to login first');
            return navigate('/welcome');
        } else if (shouldNotAuthpages.includes(viewName) && localStorage.getItem('access_token')) {
            alert('You are already logged in');
            return navigate('/');
        }
        if (viewName === "GameRemote" && !localStorage.getItem('currentSessionId')) {
            alert('You need to start a new game first');
            return navigate('/');
        }
        if (tmpAuthpages.includes(viewName) && !localStorage.getItem('tmp_access_token')){
            alert('page only in login flow');
            if(localStorage.getItem('access_token')){
                navigate('/');
            }else{
                navigate('/welcome');
            }
        }

        const View = module.default;
        if (typeof View !== 'function') {
            throw new TypeError(`${viewName} is not a constructor`);
        }

        // Create a new instance of the view
        const viewInstance = new View();

        // Unload previously loaded CSS
        unloadCSS();

        // Load the new view's CSS and wait for it to be fully applied
        if (viewInstance.cssUrl) {
            await loadCSS(viewInstance.cssUrl);
            loadedCSS.add(viewInstance.cssUrl);
        }

        // Update the #app container with the new view's HTML
        const html = await viewInstance.getHtml();
        document.querySelector('#app').innerHTML = html;

        // Initialize the new view
        if (typeof viewInstance.initialize === 'function') {
            viewInstance.initialize();
        }

        // Store the current view instance for cleanup during the next navigation
        currentViewInstance = viewInstance;

    } catch (error) {
        console.error('Error loading view:', error);
        document.querySelector('#app').innerHTML = 'Error loading view';
    }
};



export const navigate = (path) => {
    history.pushState({}, "", path);
    loadView(path);
};

window.addEventListener('popstate', () => {
    loadView(location.pathname);
});

document.addEventListener('DOMContentLoaded', async () => {
    await loadView(location.pathname);

    document.body.addEventListener('click', event => {
        const target = event.target.closest('a');
        if (target && target.href.startsWith(window.location.origin)) {
            event.preventDefault();
            const path = target.getAttribute('href');
            navigate(path);
        }
    });
});
