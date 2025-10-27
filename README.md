# 🚀 PHP Init CLI

**Generador de proyectos PHP MVC con API REST JSON y autenticación JWT**

CLI moderno y profesional para crear backends PHP siguiendo el patrón MVC, con soporte para MySQL y SQL Server, autenticación JWT, y generación automática de CRUDs.

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/usuario/php-init)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/PHP-8.0%2B-purple.svg)](https://php.net)
[![Node](https://img.shields.io/badge/Node-16%2B-green.svg)](https://nodejs.org)

---

## 📋 Tabla de Contenidos

- [Características](#-características)
- [Requisitos](#-requisitos)
- [Instalación](#-instalación)
- [Inicio Rápido](#-inicio-rápido)
- [Comandos Disponibles](#-comandos-disponibles)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [Autenticación JWT](#-autenticación-jwt)
- [Base de Datos](#-base-de-datos)
- [Rutas y Controladores](#-rutas-y-controladores)
- [Modelos](#-modelos)
- [Variables de Entorno](#-variables-de-entorno)
- [Ejemplos de Uso](#-ejemplos-de-uso)
- [Despliegue en Producción](#-despliegue-en-producción)
- [Troubleshooting](#-troubleshooting)
- [Contribuir](#-contribuir)
- [Licencia](#-licencia)

---

## ✨ Características

### Core
- 🎯 **Patrón MVC** arquitectura limpia y escalable
- 🔄 **API REST** con respuestas JSON estandarizadas
- 🗂️ **PSR-4 Autoloading** con Composer
- 🛣️ **Router** con soporte para parámetros dinámicos
- 📦 **CRUD Generator** crea modelos, controladores y rutas automáticamente
- 🔐 **Autenticación JWT** opcional con Firebase PHP-JWT
- 🌐 **CORS** configurado por defecto

### Bases de Datos
- 🐬 **MySQL** con PDO y charset UTF-8
- 🔷 **SQL Server** con driver sqlsrv
- 🔒 **Prepared Statements** para prevenir SQL Injection
- 🗄️ **Migraciones** incluidas para tabla de usuarios

### Desarrollo
- 💬 **CLI Interactivo** con Inquirer.js
- 🎨 **Mensajes de colores** y emojis en terminal
- 📝 **Configuración .env** generada automáticamente
- 🔄 **Hot reload** con servidor PHP integrado

---

## 📦 Requisitos

### Software Necesario

| Software | Versión Mínima | Descripción |
|----------|---------------|-------------|
| PHP | 8.0+ | Lenguaje backend |
| Composer | 2.0+ | Gestor de dependencias PHP |
| Node.js | 16+ | Para ejecutar el CLI |
| npm | 8+ | Gestor de paquetes Node |
| MySQL | 5.7+ | Base de datos (opcional) |
| SQL Server | 2017+ | Base de datos (opcional) |

### Extensiones PHP Requeridas

```bash
# Verificar extensiones instaladas
php -m

# Extensiones necesarias:
- pdo
- pdo_mysql (para MySQL)
- pdo_sqlsrv (para SQL Server)
- json
- mbstring
```

---

## 🔧 Instalación

### Instalación Global (Recomendada)

```bash
# Clonar repositorio
git clone https://github.com/usuario/php-init.git
cd php-init

# Instalar dependencias
npm install

# Instalar globalmente
npm link
npm install -g .

# Verificar instalación
php-init --version
```

### Instalación Local

```bash
# Instalar en proyecto actual
npm install

# Usar con npx
npx php-init new mi-proyecto
```

---

## 🚀 Inicio Rápido

### Crear un Nuevo Proyecto

```bash
# Ejecutar comando de creación
php-init new mi-api

# Responder las preguntas interactivas:
# ¿Qué base de datos usarás? → MySQL / SQL Server
# ¿Deseas autenticación JWT? → Sí / No
# Host de la base de datos: → localhost
# Puerto de la base de datos: → 3306 / 1433
# Nombre de la base de datos: → mi_base
# Usuario de la base de datos: → root / sa
# Contraseña de la base de datos: → ****
```

### Configurar y Ejecutar

```bash
# Entrar al proyecto
cd mi-api

# Instalar dependencias PHP
composer install

# Si elegiste JWT, ejecutar migración SQL
# MySQL:
mysql -u root -p mi_base < database/migrations/users.sql

# SQL Server:
sqlcmd -S localhost -U sa -P password -d mi_base -i database/migrations/users.sql

# Iniciar servidor de desarrollo
php -S localhost:8000 -t public

# Abrir en navegador
# http://localhost:8000
```

---

## 📚 Comandos Disponibles

### `new <nombre>`

Crea un nuevo proyecto PHP MVC completo.

```bash
php-init new blog-api

# Crea la estructura:
# - app/Controllers
# - app/Models
# - app/Routes
# - core/
# - public/
# - database/migrations (si se elige JWT)
```

### `make:controller <nombre>`

Genera un controlador CRUD completo.

```bash
php-init make:controller Product

# Crea: app/Controllers/ProductController.php
# Con métodos: index, show, store, update, destroy
```

### `make:model <nombre>`

Genera un modelo con conexión a base de datos.

```bash
php-init make:model Product

# Pregunta el nombre de la tabla
# Crea: app/Models/ProductModel.php
```

### `make:crud <nombre>`

Genera modelo, controlador y rutas automáticamente.

```bash
php-init make:crud Product

# Crea:
# - app/Models/ProductModel.php
# - app/Controllers/ProductController.php
# - Registra rutas en app/Routes/web.php
```

### `list:routes`

Muestra todas las rutas registradas en formato tabla.

```bash
php-init list:routes

# Salida:
# Método  | URI                  | Controlador          | Acción
# ---------------------------------------------------------------------
# GET     | /                    | Controller           | index
# POST    | /auth/register       | AuthController       | register
# POST    | /auth/login          | AuthController       | login
```

---

## 📁 Estructura del Proyecto

```
mi-api/
├── app/
│   ├── Controllers/
│   │   ├── Controller.php          # Controlador base
│   │   ├── AuthController.php      # Autenticación (si JWT)
│   │   └── ProductController.php   # Ejemplo CRUD
│   ├── Models/
│   │   ├── Model.php               # Modelo base
│   │   ├── UserModel.php           # Usuarios (si JWT)
│   │   └── ProductModel.php        # Ejemplo
│   └── Routes/
│       └── web.php                 # Definición de rutas
├── core/
│   ├── Router.php                  # Sistema de enrutamiento
│   ├── Database.php                # Conexión PDO
│   ├── Response.php                # Respuestas JSON
│   ├── Env.php                     # Carga variables .env
│   ├── JWT.php                     # Manejo de tokens (si JWT)
│   └── AuthMiddleware.php          # Middleware auth (si JWT)
├── public/
│   ├── index.php                   # Punto de entrada
│   └── .htaccess                   # Reescritura URLs
├── database/
│   └── migrations/
│       └── users.sql               # Migración usuarios (si JWT)
├── config/
├── .env                            # Variables de entorno
├── .env.example                    # Ejemplo de configuración
├── composer.json                   # Dependencias PHP
└── README.md                       # Documentación
```

---

## 🔐 Autenticación JWT

### Configuración

El sistema JWT se activa al crear el proyecto respondiendo "Sí" a la pregunta correspondiente.

**Variables de entorno generadas:**

```env
JWT_SECRET=clave_secreta_aleatoria_32_caracteres_minimo
JWT_EXPIRATION=3600  # 1 hora en segundos
```

### Endpoints Disponibles

#### 1. Registro de Usuario

```http
POST /auth/register
Content-Type: application/json

{
  "email": "usuario@example.com",
  "password": "password123",
  "name": "Juan Pérez"
}
```

**Respuesta exitosa (201):**

```json
{
  "success": true,
  "message": "Usuario registrado correctamente",
  "data": {
    "user": {
      "id": 1,
      "email": "usuario@example.com",
      "name": "Juan Pérez",
      "created_at": "2025-10-26 10:30:00"
    },
    "token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
  }
}
```

#### 2. Iniciar Sesión

```http
POST /auth/login
Content-Type: application/json

{
  "email": "usuario@example.com",
  "password": "password123"
}
```

**Respuesta exitosa (200):**

```json
{
  "success": true,
  "message": "Login exitoso",
  "data": {
    "user": {
      "id": 1,
      "email": "usuario@example.com",
      "name": "Juan Pérez"
    },
    "token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
  }
}
```

#### 3. Obtener Usuario Autenticado

```http
GET /auth/me
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```

**Respuesta exitosa (200):**

```json
{
  "success": true,
  "message": "Usuario autenticado",
  "data": {
    "id": 1,
    "email": "usuario@example.com",
    "name": "Juan Pérez",
    "created_at": "2025-10-26 10:30:00"
  }
}
```

### Proteger Rutas Personalizadas

**Método 1: En el Controlador**

```php
<?php
namespace App\Controllers;

use Core\AuthMiddleware;
use Core\Response;

class ProductController extends Controller
{
    public function index()
    {
        // Validar token y obtener usuario
        $user = AuthMiddleware::handle();
        
        // $user contiene: user_id, email, iat, exp
        $products = $this->model->all();
        
        Response::success($products, 'Productos obtenidos');
    }
}
```

**Método 2: Validación Manual**

```php
use Core\JWT;

public function store()
{
    // Validar token manualmente
    $token = JWT::getTokenFromHeader();
    if (!$token) {
        Response::error('Token no proporcionado', 401);
    }
    
    $payload = JWT::decode($token);
    if (!$payload) {
        Response::error('Token inválido', 401);
    }
    
    // Continuar con lógica...
}
```

---

## 🗄️ Base de Datos

### Conexión

La conexión se configura automáticamente con las variables `.env`:

```php
// core/Database.php maneja la conexión
$db = Database::getConnection();
```

### Configuración MySQL

```env
DB_TYPE=mysql
DB_HOST=localhost
DB_PORT=3306
DB_NAME=mi_base
DB_USER=root
DB_PASS=password
```

**DSN generado:**
```
mysql:host=localhost;port=3306;dbname=mi_base;charset=utf8mb4
```

### Configuración SQL Server

```env
DB_TYPE=sqlsrv
DB_HOST=localhost
DB_PORT=1433
DB_NAME=mi_base
DB_USER=sa
DB_PASS=password
```

**DSN generado:**
```
sqlsrv:Server=localhost,1433;Database=mi_base
```

### Migraciones

Si elegiste JWT, se genera `database/migrations/users.sql`:

**MySQL:**
```sql
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX idx_users_email ON users(email);
```

**SQL Server:**
```sql
CREATE TABLE users (
    id INT IDENTITY(1,1) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    created_at DATETIME DEFAULT GETDATE(),
    updated_at DATETIME DEFAULT GETDATE()
);

CREATE INDEX idx_users_email ON users(email);
```

---

## 🛣️ Rutas y Controladores

### Definir Rutas

Las rutas se definen en `app/Routes/web.php`:

```php
<?php

// Rutas públicas
$router->get('/', 'Controller', 'index');
$router->get('/products', 'ProductController', 'index');
$router->get('/products/{id}', 'ProductController', 'show');
$router->post('/products', 'ProductController', 'store');
$router->post('/products/{id}', 'ProductController', 'update');
$router->post('/products/{id}/delete', 'ProductController', 'destroy');

// Rutas de autenticación
$router->post('/auth/register', 'AuthController', 'register');
$router->post('/auth/login', 'AuthController', 'login');
$router->get('/auth/me', 'AuthController', 'me');
```

### Parámetros Dinámicos

```php
// Ruta con parámetro
$router->get('/users/{id}', 'UserController', 'show');

// En el controlador
public function show($id)
{
    $user = $this->model->find($id);
    Response::success($user);
}

// Múltiples parámetros
$router->get('/posts/{postId}/comments/{commentId}', 'CommentController', 'show');

public function show($postId, $commentId)
{
    // ...
}
```

### Métodos HTTP Soportados

| Método | Uso | Ejemplo |
|--------|-----|---------|
| GET | Obtener recursos | `$router->get('/users', 'UserController', 'index')` |
| POST | Crear recursos | `$router->post('/users', 'UserController', 'store')` |
| PUT | Actualizar completo | `$router->put('/users/{id}', 'UserController', 'update')` |
| DELETE | Eliminar recursos | `$router->delete('/users/{id}', 'UserController', 'destroy')` |

---

## 📊 Modelos

### Modelo Base

Todos los modelos heredan de `Model.php`:

```php
<?php
namespace App\Models;

class ProductModel extends Model
{
    protected $table = 'products';
    
    // Métodos heredados:
    // - all()
    // - find($id)
    // - create($data)
    // - update($id, $data)
    // - delete($id)
}
```

### Métodos Disponibles

#### `all(): array`

Obtiene todos los registros de la tabla.

```php
$products = $this->model->all();
// SELECT * FROM products
```

#### `find($id): array|false`

Busca un registro por ID.

```php
$product = $this->model->find(1);
// SELECT * FROM products WHERE id = 1
```

#### `create(array $data): array|false`

Crea un nuevo registro.

```php
$data = [
    'name' => 'Laptop',
    'price' => 999.99,
    'stock' => 10
];
$product = $this->model->create($data);
// INSERT INTO products (name, price, stock) VALUES (?, ?, ?)
```

#### `update($id, array $data): array|false`

Actualiza un registro existente.

```php
$data = ['price' => 899.99];
$product = $this->model->update(1, $data);
// UPDATE products SET price = ? WHERE id = ?
```

#### `delete($id): bool`

Elimina un registro.

```php
$success = $this->model->delete(1);
// DELETE FROM products WHERE id = ?
```

### Métodos Personalizados

Puedes agregar métodos específicos a tus modelos:

```php
<?php
namespace App\Models;

class ProductModel extends Model
{
    protected $table = 'products';
    
    public function findByCategory(string $category): array
    {
        $stmt = $this->db->prepare("SELECT * FROM {$this->table} WHERE category = ?");
        $stmt->execute([$category]);
        return $stmt->fetchAll();
    }
    
    public function lowStock(int $limit = 10): array
    {
        $stmt = $this->db->prepare("SELECT * FROM {$this->table} WHERE stock < ?");
        $stmt->execute([$limit]);
        return $stmt->fetchAll();
    }
}
```

---

## 🌍 Variables de Entorno

### Archivo .env

```env
# Base de datos
DB_TYPE=mysql
DB_HOST=localhost
DB_PORT=3306
DB_NAME=mi_base
DB_USER=root
DB_PASS=password

# JWT (si está habilitado)
JWT_SECRET=clave_secreta_minimo_32_caracteres
JWT_EXPIRATION=3600

# Aplicación (opcional)
APP_NAME="Mi API"
APP_ENV=development
APP_DEBUG=true
```

### Acceder a Variables

```php
// En cualquier parte del código PHP
$dbHost = getenv('DB_HOST');
$jwtSecret = getenv('JWT_SECRET');
$appName = getenv('APP_NAME') ?: 'Default Name';
```

---

## 💡 Ejemplos de Uso

### Ejemplo 1: API de Blog

```bash
# Crear proyecto
php-init new blog-api

# Crear recursos
cd blog-api
composer install
php-init make:crud Post
php-init make:crud Comment
php-init make:crud Category

# Ejecutar migración de usuarios
mysql -u root -p blog < database/migrations/users.sql

# Iniciar servidor
php -S localhost:8000 -t public
```

### Ejemplo 2: E-commerce Backend

```bash
# Crear proyecto con JWT
php-init new shop-api

# Crear modelos de negocio
cd shop-api
composer install
php-init make:crud Product
php-init make:crud Order
php-init make:crud Customer

# Agregar método personalizado en ProductModel.php
```

```php
public function featured(): array
{
    return $this->db->query("SELECT * FROM products WHERE featured = 1")->fetchAll();
}
```

### Ejemplo 3: Sistema de Tareas

```bash
php-init new tasks-api
cd tasks-api
composer install
php-init make:crud Task
```

**Personalizar TaskController.php:**

```php
public function byStatus($status)
{
    try {
        $stmt = $this->model->db->prepare("SELECT * FROM tasks WHERE status = ?");
        $stmt->execute([$status]);
        $tasks = $stmt->fetchAll();
        Response::success($tasks, 'Tareas obtenidas');
    } catch (\Exception $e) {
        Response::error('Error: ' . $e->getMessage(), 500);
    }
}
```

**Agregar ruta en web.php:**

```php
$router->get('/tasks/status/{status}', 'TaskController', 'byStatus');
```

---

## 🚢 Despliegue en Producción

### Checklist de Seguridad

- [ ] Cambiar `JWT_SECRET` a una clave robusta única
- [ ] Establecer `APP_ENV=production`
- [ ] Deshabilitar errores detallados
- [ ] Configurar HTTPS
- [ ] Validar todos los inputs
- [ ] Implementar rate limiting
- [ ] Revisar permisos de archivos
- [ ] Usar `.env` con permisos restringidos (600)
- [ ] Configurar backup de base de datos

### Configuración Apache

```apache
<VirtualHost *:80>
    ServerName api.ejemplo.com
    DocumentRoot /var/www/api/public
    
    <Directory /var/www/api/public>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    ErrorLog ${APACHE_LOG_DIR}/api-error.log
    CustomLog ${APACHE_LOG_DIR}/api-access.log combined
</VirtualHost>
```

### Configuración Nginx

```nginx
server {
    listen 80;
    server_name api.ejemplo.com;
    root /var/www/api/public;
    
    index index.php;
    
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
    
    location ~ /\.(?!well-known).* {
        deny all;
    }
}
```

### Optimización

```bash
# Optimizar autoload de Composer
composer dump-autoload --optimize --no-dev

# Deshabilitar xdebug en producción
sudo phpdismod xdebug

# Configurar OPcache en php.ini
opcache.enable=1
opcache.memory_consumption=128
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=10000
opcache.validate_timestamps=0
```

---

## 🔧 Troubleshooting

### Error: "Class not found"

```bash
# Regenerar autoload
composer dump-autoload
```

### Error: Conexión a base de datos

```bash
# Verificar extensión PDO
php -m | grep pdo

# MySQL
php -m | grep pdo_mysql

# SQL Server
php -m | grep pdo_sqlsrv

# Verificar credenciales en .env
cat .env
```

### Error: "Token inválido"

- Verificar que el header `Authorization` tenga formato: `Bearer {token}`
- Verificar que `JWT_SECRET` sea el mismo en servidor
- Verificar que el token no haya expirado

### Error: CORS

Si tienes problemas con CORS desde frontend:

```php
// En public/index.php, agregar:
header('Access-Control-Allow-Origin: https://tu-frontend.com');
header('Access-Control-Allow-Credentials: true');
```

### Error: 404 en todas las rutas

```bash
# Verificar mod_rewrite en Apache
sudo a2enmod rewrite
sudo systemctl restart apache2

# Verificar .htaccess en public/
ls -la public/.htaccess
```

---

## 🤝 Contribuir

¡Las contribuciones son bienvenidas!

### Proceso

1. Fork el repositorio
2. Crea una rama: `git checkout -b feature/nueva-funcionalidad`
3. Commit cambios: `git commit -am 'Agregar nueva funcionalidad'`
4. Push: `git push origin feature/nueva-funcionalidad`
5. Abre un Pull Request

### Guidelines

- Seguir principio KISS (Keep It Simple, Stupid)
- Mantener código limpio y documentado
- Agregar tests si es posible
- Actualizar README si es necesario

---

## 📝 Licencia

Este proyecto está bajo la Licencia MIT. Ver archivo [LICENSE](LICENSE) para más detalles.

---

## 👨‍💻 Autor

**Tu Nombre**
- GitHub: [@usuario](https://github.com/usuario)
- Email: usuario@example.com

---

## 🙏 Agradecimientos

- [Composer](https://getcomposer.org/)
- [Firebase PHP-JWT](https://github.com/firebase/php-jwt)
- [Commander.js](https://github.com/tj/commander.js)
- [Inquirer.js](https://github.com/SBoudrias/Inquirer.js)

---

## 📊 Estadísticas

![GitHub stars](https://img.shields.io/github/stars/usuario/php-init?style=social)
![GitHub forks](https://img.shields.io/github/forks/usuario/php-init?style=social)
![GitHub issues](https://img.shields.io/github/issues/usuario/php-init)

---

**¿Tienes preguntas?** Abre un [issue](https://github.com/usuario/php-init/issues) o contacta al equipo.

**¡Happy coding!** 🚀✨
