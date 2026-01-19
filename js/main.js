import SecurityCore from './security.js';

const App = {
    init() {
        const security = SecurityCore.getInstance();
        const container = document.getElementById('app');

        // DRY: Una sola función para renderizar componentes
        this.render(container, `
            <p class="has-text-success">Sistema Inicializado Correctamente.</p>
            <p>Sanitización activa: ${security.sanitize("<script>alert('hack')</script>")}</p>
        `);
    },
    render(el, html) {
        el.innerHTML = html;
    }
};

document.addEventListener('DOMContentLoaded', () => App.init());
