package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"regexp"
)

// --- MODELO DE DATOS ---

type Concepto struct {
	Slug        string   `json:"slug"`
	Titulo      string   `json:"titulo"`
	Descripcion string   `json:"descripcion"`
	Ejemplo     string   `json:"ejemplo"`
	Mitigacion  []string `json:"mitigacion"`
	OwaspURL    string   `json:"owasp_url"`
}

// Singleton de datos de ciberseguridad
var listaConceptos = []Concepto{
	{Slug: "xss", Titulo: "Cross-Site Scripting (XSS)", Descripcion: "Inyección de scripts en sitios web.", Ejemplo: "<script>alert(document.cookie)</script>", Mitigacion: []string{"Sanitizar HTML", "CSP"}, OwaspURL: "https://owasp.org/www-community/attacks/xss/"},
	{Slug: "sql-injection", Titulo: "SQL Injection", Descripcion: "Manipulación de consultas a la base de datos.", Ejemplo: "admin' OR 1=1 --", Mitigacion: []string{"Prepared Statements", "Validación"}, OwaspURL: "https://owasp.org/www-community/attacks/SQL_Injection"},
	{Slug: "phishing", Titulo: "Phishing", Descripcion: "Suplantación de identidad para robo de datos.", Ejemplo: "Email falso de banco pidiendo login.", Mitigacion: []string{"2FA", "Educación", "DMARC"}, OwaspURL: "https://owasp.org/www-community/attacks/Phishing"},
	{Slug: "dos", Titulo: "DoS / DDoS", Descripcion: "Agotamiento de recursos del servidor.", Ejemplo: "Inundación de peticiones HTTP.", Mitigacion: []string{"Rate Limiting", "WAF", "CDN"}, OwaspURL: "https://owasp.org/www-community/attacks/Denial_of_Service"},
	{Slug: "brute-force", Titulo: "Fuerza Bruta", Descripcion: "Prueba masiva de contraseñas.", Ejemplo: "Diccionario de 10 millones de claves.", Mitigacion: []string{"Bloqueo de IP", "Captcha"}, OwaspURL: "https://owasp.org/www-community/attacks/Brute_force_attack"},
	{Slug: "mitm", Titulo: "Man-in-the-Middle", Descripcion: "Intercepción de comunicaciones.", Ejemplo: "Sniffing en WiFi pública.", Mitigacion: []string{"HSTS", "TLS 1.3"}, OwaspURL: "https://owasp.org/www-community/attacks/Man-in-the-middle_attack"},
	{Slug: "ransomware", Titulo: "Ransomware", Descripcion: "Cifrado de archivos con extorsión.", Ejemplo: "WannaCry / LockBit.", Mitigacion: []string{"Backups Offline", "EDR"}, OwaspURL: "https://www.owasp.org/index.php/Malware"},
	{Slug: "zero-day", Titulo: "Zero-Day Exploit", Descripcion: "Ataque a falla no conocida.", Ejemplo: "Falla en kernel antes del parche.", Mitigacion: []string{"Virtual Patching", "Sandboxing"}, OwaspURL: "https://owasp.org/www-community/vulnerabilities/Zero_Day_Vulnerability"},
	{Slug: "social-engineering", Titulo: "Ingeniería Social", Descripcion: "Manipulación psicológica humana.", Ejemplo: "Llamada de 'soporte técnico'.", Mitigacion: []string{"Protocolos de Verificación"}, OwaspURL: "https://owasp.org/www-community/attacks/Social_Engineering"},
	{Slug: "malware", Titulo: "Malware", Descripcion: "Software malicioso general.", Ejemplo: "Troyanos, Gusanos, Spyware.", Mitigacion: []string{"Antivirus", "Privilegios Mínimos"}, OwaspURL: "https://owasp.org/www-community/attacks/Malware"},
	{Slug: "broken-auth", Titulo: "Autenticación Deficiente", Descripcion: "Fallas en gestión de sesiones.", Ejemplo: "IDs de sesión predecibles.", Mitigacion: []string{"Gestores de sesión seguros"}, OwaspURL: "https://owasp.org/www-project-top-ten/2017/A2_Broken_Authentication"},
	{Slug: "idors", Titulo: "IDOR", Descripcion: "Referencia directa a objetos insegura.", Ejemplo: "/api/user/10 -> /api/user/11.", Mitigacion: []string{"Control de acceso por usuario"}, OwaspURL: "https://owasp.org/www-project-top-ten/2017/A4_Insecure_Direct_Object_References"},
	{Slug: "security-misconf", Titulo: "Mala Configuración", Descripcion: "Servicios con ajustes por defecto.", Ejemplo: "Panel admin sin clave o puerto 22 abierto.", Mitigacion: []string{"Hardening de servidores"}, OwaspURL: "https://owasp.org/www-project-top-ten/2017/A6_Security_Misconfiguration"},
	{Slug: "clickjacking", Titulo: "Clickjacking", Descripcion: "Engaño para hacer clic en capas ocultas.", Ejemplo: "Botón 'Me gusta' invisible sobre un juego.", Mitigacion: []string{"X-Frame-Options: DENY"}, OwaspURL: "https://owasp.org/www-community/attacks/Clickjacking"},
	{Slug: "csrf", Titulo: "CSRF", Descripcion: "Peticiones no autorizadas del usuario.", Ejemplo: "Link que cambia clave sin preguntar.", Mitigacion: []string{"Tokens Anti-CSRF", "SameSite Cookies"}, OwaspURL: "https://owasp.org/www-community/attacks/csrf"},
	{Slug: "directory-traversal", Titulo: "Directory Traversal", Descripcion: "Acceso a archivos fuera de la web root.", Ejemplo: "../../etc/passwd.", Mitigacion: []string{"Validación de rutas", "Chroot"}, OwaspURL: "https://owasp.org/www-community/attacks/Path_Traversal"},
	{Slug: "logic-bombs", Titulo: "Bombas Lógicas", Descripcion: "Código que se ejecuta tras una condición.", Ejemplo: "Borrar DB si un empleado es despedido.", Mitigacion: []string{"Revisión de código", "Separación de tareas"}, OwaspURL: "https://owasp.org/www-community/attacks/Logic_Bomb"},
	{Slug: "supply-chain", Titulo: "Ataque a Cadena de Suministro", Descripcion: "Compromiso de librerías externas.", Ejemplo: "Inyección de código en NPM/PyPI.", Mitigacion: []string{"SCA (Software Composition Analysis)"}, OwaspURL: "https://owasp.org/www-community/attacks/Supply_Chain_Attack"},
	{Slug: "cryptojacking", Titulo: "Cryptojacking", Descripcion: "Uso de CPU ajena para minar cripto.", Ejemplo: "Script de minería oculto en el navegador.", Mitigacion: []string{"Bloqueadores de scripts", "Monitoreo de CPU"}, OwaspURL: "https://owasp.org/www-community/attacks/Cryptojacking"},
	{Slug: "insider-threat", Titulo: "Amenaza Interna", Descripcion: "Ataque perpetrado por alguien de la empresa.", Ejemplo: "Robo de secretos por un administrador.", Mitigacion: []string{"DLP (Data Loss Prevention)", "Auditoría"}, OwaspURL: "https://owasp.org/www-community/attacks/Insider_Threat"},
}

// --- MIDDLEWARES ---

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CSP Estricta: Solo permite scripts locales y estilos esenciales
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:;")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// --- CONTROLADORES (HANDLERS) ---

func main() {
	// 1. Servir archivos estáticos (CSS/JS)
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// 2. Ruta Home (Index)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		renderTemplate(w, "index", listaConceptos)
	})

	// 3. Ruta de Detalle (SEO Friendly)
	http.HandleFunc("/concepto/", func(w http.ResponseWriter, r *http.Request) {
		slug := r.URL.Path[len("/concepto/"):]
		var encontrado *Concepto
		for _, c := range listaConceptos {
			if c.Slug == slug {
				encontrado = &c
				break
			}
		}
		if encontrado == nil {
			http.NotFound(w, r)
			return
		}
		renderTemplate(w, "detalle", encontrado)
	})

	// 4. API: Simulador de Escaneo de Vulnerabilidades (POST)
	http.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método no permitido", 405)
			return
		}

		codigo := r.FormValue("codigo")
		// Regex para detectar patrones peligrosos
		patrones := `(?i)(<script|SELECT|DROP|DELETE|OR 1=1|document\.cookie|eval\()`
		match, _ := regexp.MatchString(patrones, codigo)

		response := map[string]string{
			"status": "seguro",
			"msg":    "✅ No se detectaron patrones de ataque obvios.",
		}
		if match {
			response["status"] = "peligroso"
			response["msg"] = "⚠️ Alerta: Se detectó un patrón de ataque potencial (Inyección/XSS)."
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	log.Println("🚀 Servidor Ciber-Educativo en http://localhost:8081")
	log.Fatal(http.ListenAndServe(":8081", securityHeaders(http.DefaultServeMux)))
}

// Helper para renderizar plantillas (Evita repetición - DRY)
func renderTemplate(w http.ResponseWriter, tmplName string, data interface{}) {
	tmpl, err := template.ParseFiles("templates/layout.html", "templates/"+tmplName+".html")
	if err != nil {
		log.Printf("Error en plantilla: %v", err)
		http.Error(w, "Error interno", 500)
		return
	}
	tmpl.ExecuteTemplate(w, "layout", data)
}
