// Patrón Singleton: Solo una instancia de configuración de seguridad
const SecurityCore = (function() {
    let instance;

    function createInstance() {
        return {
            cspNonce: btoa(Math.random().toString()), // Generar un nonce básico
            sanitize: (str) => {
                const temp = document.createElement('div');
                temp.textContent = str;
                return temp.innerHTML; // Evita XSS convirtiendo HTML en texto plano
            }
        };
    }

    return {
        getInstance: function() {
            if (!instance) instance = createInstance();
            return instance;
        }
    };
})();

export default SecurityCore;