# PHP-Init 🚀

**CLI para crear backends PHP MVC con API REST JSON y autenticación JWT**

Una herramienta de línea de comandos moderna y completa para inicializar y gestionar proyectos backend en PHP con arquitectura MVC, API REST JSON, y un potente sistema de autenticación JWT.

---

## ✨ Características Principales

- 🏗️ **Arquitectura MVC limpia** con separación de responsabilidades
- 🔐 **Autenticación JWT completa** con refresh tokens y revocación
- 🛡️ **Sistema de middleware robusto** con soporte para middlewares personalizados
- ✅ **Validación de datos** con reglas flexibles y extensibles
- 🚦 **Rate limiting avanzado** con file locks y limpieza automática
- 📝 **Logging estructurado** con rotación automática y sanitización de datos sensibles
- 🔒 **Seguridad robusta** con protección contra SQL Injection y XSS
- 🗄️ **Soporte multi-base de datos** (MySQL y SQL Server)
- 🌐 **CORS configurable** para desarrollo y producción
- 🎯 **Health checks** automáticos para monitoreo
- 🧪 **Generación de tests** con PHPUnit
- 🔄 **Múltiples entornos** (.env.dev, .env.test, .env.prod)
- ⚡ **CLI intuitiva** con comandos tipo Artisan/Rails

---

## 📦 Instalación

### Requisitos

- PHP 8.0 o superior
- Composer
- Node.js y npm (para la CLI)
- MySQL o SQL Server

### Instalación Global

```bash
npm install -g php-init
```

### Instalación desde el código fuente

```bash
git clone https://github.com/jfrem/cli_php.git
cd cli_php
npm install
npm link
```

---

## 🚀 Inicio Rápido

### 1. Crear un nuevo proyecto

```bash
php-init new mi-proyecto
```

La CLI te guiará a través de una configuración interactiva:
- Selección de base de datos (MySQL o SQL Server)
- Autenticación JWT (opcional)
- Configuración de credenciales de base de datos

### 2. Instalar dependencias

```bash
cd mi-proyecto
composer install
```

### 3. Configurar la base de datos

Si elegiste autenticación JWT, ejecuta las migraciones en orden:

```bash
php-init db:migrate
```

### 4. Iniciar el servidor

```bash
php-init server
```

El servidor estará disponible en `http://localhost:8000`

---

## 📚 Comandos CLI

### Crear Proyecto

```bash
php-init new <nombre>
```

Crea un nuevo proyecto PHP MVC con toda la estructura necesaria.

#### Opciones no interactivas

También puedes crear un proyecto de forma no interactiva usando las siguientes opciones:

```bash
php-init new <nombre> --database <type> --jwt --db-host <host> --db-port <port> --db-name <name> --db-user <user> --db-pass <pass>
```

-   `--database <type>`: Tipo de base de datos (mysql o sqlsrv)
-   `--jwt`: Incluir autenticación JWT
-   `--db-host <host>`: Host de la base de datos
-   `--db-port <port>`: Puerto de la base de datos
-   `--db-name <name>`: Nombre de la base de datos
-   `--db-user <user>`: Usuario de la base de datos
-   `--db-pass <pass>`: Contraseña de la base de datos

### Generar Código

#### Controlador CRUD

```bash
php-init make:controller Producto
```

Genera un controlador con todos los métodos CRUD: `index`, `show`, `store`, `update`, `destroy`.

#### Modelo

```bash
php-init make:model Producto
```

Crea un modelo con operaciones básicas de base de datos.

#### Middleware Personalizado

```bash
php-init make:middleware Admin
```

Genera un middleware personalizado que puedes usar para proteger rutas.

#### CRUD Completo

```bash
php-init make:crud Producto
```

Genera controlador, modelo y rutas CRUD en un solo comando.

#### Test

```bash
php-init make:test Producto
```

Crea una plantilla de test con PHPUnit.

### Utilidades

#### Listar Rutas

```bash
php-init list:routes
```

Muestra todas las rutas registradas en tu aplicación con formato tabular.

#### Servidor de Desarrollo

```bash
php-init server
```

#### Ejecutar Migraciones

```bash
php-init db:migrate
```

Inicia el servidor de desarrollo de PHP con configuración interactiva de host y puerto.

---

## 🏗️ Estructura del Proyecto

```
mi-proyecto/
├── app/
│   ├── Controllers/          # Controladores de la aplicación
│   │   ├── Controller.php    # Controlador base
│   │   ├── AuthController.php # Autenticación JWT
│   │   └── HealthController.php # Health checks
│   ├── Models/               # Modelos de datos
│   │   ├── Model.php         # Modelo base con CRUD
│   │   ├── UserModel.php     # Modelo de usuarios
│   │   ├── JwtDenylistModel.php # Revocación de tokens
│   │   └── RefreshTokenModel.php # Refresh tokens
│   └── Routes/
│       └── web.php           # Definición de rutas
├── core/                     # Núcleo del framework
│   ├── Router.php            # Sistema de enrutamiento
│   ├── Route.php             # Clase de ruta individual
│   ├── Middleware.php        # Gestor de middlewares
│   ├── AuthMiddleware.php    # Middleware de autenticación
│   ├── Response.php          # Respuestas JSON estandarizadas
│   ├── Validator.php         # Validación de datos
│   ├── Logger.php            # Sistema de logs
│   ├── RateLimit.php         # Control de tasa de peticiones
│   ├── Database.php          # Conexión a base de datos
│   ├── Env.php               # Carga de variables de entorno
│   └── JWT.php               # Manejo de JSON Web Tokens
├── database/
│   └── migrations/           # Migraciones SQL
│       ├── users.sql
│       ├── jwt_denylist.sql
│       └── refresh_tokens.sql
├── logs/                     # Archivos de log (rotación automática)
├── public/                   # Directorio público
│   ├── index.php             # Punto de entrada
│   └── .htaccess             # Reglas de reescritura Apache
├── tests/                    # Tests automatizados
├── .env                      # Variables de entorno (actual)
├── .env.dev                  # Variables de desarrollo
├── .env.test                 # Variables de testing
├── .env.prod                 # Variables de producción
├── .env.example              # Ejemplo de variables
├── .gitignore
├── composer.json
└── README.md
```

---

## 🔐 Autenticación JWT

### Flujo de Autenticación

#### 1. Registro de Usuario

```bash
POST /auth/register
Content-Type: application/json

{
  "email": "usuario@example.com",
  "password": "password123",
  "name": "Usuario Ejemplo"
}
```

**Respuesta:**

```json
{
  "success": true,
  "message": "Usuario registrado correctamente",
  "data": {
    "user": {
      "id": 1,
      "email": "usuario@example.com",
      "name": "Usuario Ejemplo",
      "created_at": "2025-01-15 10:30:00"
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

#### 2. Inicio de Sesión

```bash
POST /auth/login
Content-Type: application/json

{
  "email": "usuario@example.com",
  "password": "password123"
}
```

**Respuesta:**

```json
{
  "success": true,
  "message": "Login exitoso",
  "data": {
    "user": {
      "id": 1,
      "email": "usuario@example.com",
      "name": "Usuario Ejemplo"
    },
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

**Nota:** El `refresh_token` se envía de forma segura como una cookie `HttpOnly`, por lo que no es visible en la respuesta JSON.

#### 3. Refrescar Token

```bash
POST /auth/refresh
```

**Nota:** Este endpoint no requiere un cuerpo de solicitud. El `refresh_token` se lee automáticamente de la cookie `HttpOnly`.

#### 4. Cerrar Sesión

```bash
POST /auth/logout
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### 5. Obtener Usuario Autenticado

```bash
GET /auth/me
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Configuración JWT

En tu archivo `.env`:

```env
# JWT Configuration
JWT_SECRET=tu_secreto_super_seguro_de_minimo_32_caracteres
JWT_ACCESS_TOKEN_EXPIRATION=900          # 15 minutos
JWT_REFRESH_TOKEN_EXPIRATION=2592000    # 30 días
```

**⚠️ IMPORTANTE:** En producción, el `JWT_SECRET` debe ser:
- Único y aleatorio
- Mínimo 32 caracteres
- Diferente del valor por defecto

---

## 🛡️ Sistema de Middleware

### Uso Básico

```php
// En app/Routes/web.php

// Ruta pública
$router->get('/public', 'PublicController', 'index');

// Ruta protegida con autenticación
$router->get('/profile', 'ProfileController', 'show')->middleware('auth');

// Múltiples middlewares
$router->get('/admin/users', 'AdminController', 'users')
    ->middleware('auth', 'admin');
```

### Crear Middleware Personalizado

#### 1. Generar el middleware

```bash
php-init make:middleware Admin
```

#### 2. Implementar la lógica

Edita `core/AdminMiddleware.php`:

```php
<?php
namespace Core;

class AdminMiddleware
{
    public static function handle(): void
    {
        // Obtener usuario autenticado
        $user = AuthMiddleware::getAuthUser();
        
        // Verificar que existe y es admin
        if (!$user || !isset($user->role) || $user->role !== 'admin') {
            Logger::error('Acceso denegado: usuario no es admin');
            Response::error('Acceso denegado', 403);
        }
        
        // Si todo está bien, el flujo continúa
        Logger::info('Middleware Admin ejecutado correctamente');
    }
}
```

#### 3. Registrar el middleware

En `public/index.php`:

```php
Middleware::register('admin', 'Core\\AdminMiddleware::handle');
```

#### 4. Usar en rutas

```php
$router->delete('/users/{id}', 'UserController', 'destroy')
    ->middleware('auth', 'admin');
```

### Acceder al Usuario Autenticado

En cualquier controlador protegido con el middleware `auth`:

```php
use Core\AuthMiddleware;

public function myMethod()
{
    $user = AuthMiddleware::getAuthUser();
    // $user contiene: { user_id, email, jti, iat, exp }
    
    echo "Usuario autenticado: " . $user->email;
}
```

---

## ✅ Validación de Datos

### Uso Básico

```php
use Core\Validator;

$data = $this->getBody();

$errors = Validator::validate($data, [
    'email' => 'required|email',
    'password' => 'required|min:6|max:50',
    'age' => 'numeric',
    'username' => 'required|alpha'
]);

if (!empty($errors)) {
    Response::error('Errores de validación', 422, $errors);
}
```

### Reglas Disponibles

| Regla | Descripción | Ejemplo |
|-------|-------------|---------|
| `required` | Campo obligatorio | `'email' => 'required'` |
| `email` | Formato de email válido | `'email' => 'required\|email'` |
| `min:n` | Longitud mínima de n caracteres | `'password' => 'min:6'` |
| `max:n` | Longitud máxima de n caracteres | `'password' => 'max:50'` |
| `numeric` | Solo números | `'age' => 'numeric'` |
| `alpha` | Solo letras | `'username' => 'alpha'` |

### Respuesta de Error de Validación

```json
{
  "success": false,
  "message": "Errores de validación",
  "errors": {
    "email": ["El campo email es requerido", "El campo email debe ser un email válido"],
    "password": ["El campo password debe tener al menos 6 caracteres"]
  }
}
```

---

## 📝 Sistema de Logging

### Uso

```php
use Core\Logger;

// Información general
Logger::info('Usuario registrado exitosamente', [
    'user_id' => $user['id']
]);

// Advertencias
Logger::warning('Intento de login fallido', [
    'email' => $email
]);

// Errores
Logger::error('Error de conexión a la base de datos', [
    'exception' => $e
]);
```

### Características

- **Formato JSON estructurado** para fácil parsing
- **Rotación automática** de logs (retención de 7 días)
- **Sanitización automática** de datos sensibles (passwords, tokens, secrets)
- **Stack trace completo** para excepciones
- **Archivos por fecha**: `logs/app-2025-01-15.log`

### Ejemplo de Log

```json
{
  "timestamp": "2025-01-15T10:30:45+00:00",
  "level": "ERROR",
  "message": "Error de BD en login [ID: err_abc123]",
  "context": {
    "exception": {
      "class": "PDOException",
      "message": "SQLSTATE[HY000]: General error",
      "file": "/path/to/file.php:123",
      "trace": "..."
    }
  }
}
```

---

## 🚦 Rate Limiting

### Configuración por Defecto

- **Límite**: 100 peticiones por minuto por IP
- **Método**: File-based con locks para prevenir race conditions
- **Limpieza**: Automática de entradas antiguas

### Personalizar Rate Limit

Edita `public/index.php`:

```php
// 50 peticiones cada 2 minutos
RateLimit::check($clientIp, 50, 120);
```

### Características

- **File locking** para prevenir condiciones de carrera
- **Limpieza automática** de IPs antiguas (1% de probabilidad por request)
- **Almacenamiento JSON** con locks para consistencia
- **Bloqueo temporal** cuando se excede el límite

---

## 🔒 Seguridad

### Protección SQL Injection

- **Prepared statements** en todas las consultas
- **Escapado automático** de identificadores de tabla/columna
- **Sanitización** de parámetros de ruta

```php
// El framework hace esto automáticamente
protected function escapeIdentifier(string $identifier): string
{
    return '`' . str_replace('`', '``', $identifier) . '`';
}
```

### Seguridad JWT

- ✅ Validación estricta de `JWT_SECRET` en producción
- ✅ Refresh tokens con rotación automática
- ✅ Revocación de tokens (denylist) con limpieza automática
- ✅ JWT ID único (jti) para rastreo individual
- ✅ Expiración configurable de access y refresh tokens

### Logging Seguro

Los siguientes campos se sanitizan automáticamente:
- `password`
- `token`
- `secret`
- `api_key`
- `credit_card`
- `authorization`

### CORS

Configuración por entorno en `.env`:

```env
# Desarrollo
APP_ENV=development
# Permite todos los orígenes (*)

# Producción
APP_ENV=production
ALLOWED_ORIGINS=https://tudominio.com,https://app.tudominio.com
```

---

## 🗄️ Manejo de Base de Datos

### MySQL

```env
DB_TYPE=mysql
DB_HOST=localhost
DB_PORT=3306
DB_NAME=mi_base
DB_USER=root
DB_PASS=password
```

### SQL Server

```env
DB_TYPE=sqlsrv
DB_HOST=localhost
DB_PORT=1433
DB_NAME=mi_base
DB_USER=sa
DB_PASS=password
```

### Operaciones CRUD en Modelos

```php
// Obtener todos los registros
$productos = $this->model->all();

// Buscar por ID
$producto = $this->model->find($id);

// Crear
$nuevo = $this->model->create([
    'nombre' => 'Producto X',
    'precio' => 99.99
]);

// Actualizar
$actualizado = $this->model->update($id, [
    'precio' => 89.99
]);

// Eliminar
$this->model->delete($id);
```

---

## 🌍 Múltiples Entornos

El framework genera automáticamente archivos de configuración para diferentes entornos:

- `.env` - Configuración activa (no commitear a Git)
- `.env.dev` - Desarrollo
- `.env.test` - Testing
- `.env.prod` - Producción
- `.env.example` - Plantilla de ejemplo

### Cambiar entre entornos

```bash
# Desarrollo
cp .env.dev .env

# Testing
cp .env.test .env

# Producción
cp .env.prod .env
```

---

## 🏥 Health Check

Endpoint automático para monitoreo:

```bash
GET /health
```

**Respuesta:**

```json
{
  "success": true,
  "message": "Operación exitosa",
  "data": {
    "status": "healthy",
    "timestamp": 1642234567,
    "services": {
      "database": "connected"
    }
  }
}
```

---

## 🚀 Despliegue en Producción

### 1. Configurar Variables de Entorno

```env
APP_ENV=production
JWT_SECRET=<genera-uno-seguro-de-64-caracteres>
ALLOWED_ORIGINS=https://tudominio.com,https://app.tudominio.com
```

### 2. Optimizar Composer

```bash
composer install --no-dev --optimize-autoloader
```

### 3. Configurar Servidor Web

#### Apache

Asegúrate de que `.htaccess` esté habilitado:

```apache
<VirtualHost *:80>
    DocumentRoot /var/www/html/public
    <Directory /var/www/html/public>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

#### Nginx

```nginx
server {
    listen 80;
    server_name tudominio.com;
    root /var/www/html/public;
    index index.php;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.0-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
}
```

### 4. Permisos

```bash
chmod -R 755 /var/www/html
chmod -R 775 logs/
```

### 5. SSL/TLS

Usa Let's Encrypt para certificados gratuitos:

```bash
certbot --nginx -d tudominio.com
```

---

## 📊 Mejores Prácticas

### Seguridad

- ✅ Usar HTTPS en producción
- ✅ Generar un `JWT_SECRET` robusto (64+ caracteres)
- ✅ Configurar `ALLOWED_ORIGINS` específicos en producción
- ✅ Mantener logs fuera del directorio público
- ✅ Usar prepared statements (el framework lo hace automáticamente)
- ✅ Validar todos los inputs del usuario
- ✅ Implementar rate limiting apropiado

### Performance

- ✅ Usar Redis para rate limiting en múltiples servidores
- ✅ Cachear respuestas frecuentes
- ✅ Optimizar índices de base de datos
- ✅ Usar `composer install --optimize-autoloader` en producción

### Mantenimiento

- ✅ Monitorear logs regularmente
- ✅ Configurar backups automáticos de la base de datos
- ✅ Implementar alertas de errores (Sentry, Datadog)
- ✅ Documentar APIs con OpenAPI/Swagger

---

## 🧪 Testing

Genera tests con:

```bash
php-init make:test Producto
```

Ejecuta tests con PHPUnit:

```bash
./vendor/bin/phpunit tests/
```

---

## 🤝 Contribuir

Las contribuciones son bienvenidas! Por favor:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

---

## 📄 Licencia

Este proyecto está bajo la licencia MIT. Ver el archivo `LICENSE` para más detalles.

---

## 👨‍💻 Autor

**Jhon Fredy Murillo**
- GitHub: [@jfrem](https://github.com/jfrem)

---

## 🙏 Agradecimientos

- Inspirado por Laravel Artisan y Ruby on Rails
- JWT implementation by Firebase
- Comunidad PHP

---

## 📞 Soporte

Si encuentras algún problema o tienes preguntas:

- 🐛 [Reportar un bug](https://github.com/jfrem/cli_php/issues)
- 💬 [Discusiones](https://github.com/jfrem/cli_php/discussions)
---

**⭐ Si este proyecto te fue útil, considera darle una estrella en GitHub!**
