#!/usr/bin/env node
import { Command } from "commander";
import inquirer from "inquirer";
import fs from "fs-extra";
import path from "path";
import crypto from "crypto";

const program = new Command();

program
    .name("php-init")
    .description("CLI para crear backend PHP MVC con API REST JSON")
    .version("4.4.0");

// ==============================
// Utilidades simples
// ==============================

const cap = (str) => str.charAt(0).toUpperCase() + str.slice(1);

const write = (base, file, content) => {
    const full = path.join(base, file);
    fs.ensureDirSync(path.dirname(full));
    fs.writeFileSync(full, content.trim() + '\n', "utf8");
};

const exists = (file) => fs.existsSync(file);

const inProject = () => ['composer.json', 'app', 'core'].some(m =>
    exists(path.join(process.cwd(), m))
);

const error = (msg) => {
    console.error(`❌ ${msg}`);
    process.exit(1);
};

const success = (msg) => console.log(`✅ ${msg}`);
const warn = (msg) => console.log(`⚠️  ${msg}`);

// ==============================
// Templates simplificados
// ==============================

const t = {
    composer: (withJWT) => `{
  "name": "usuario/php-backend",
  "description": "Backend PHP MVC con API REST JSON",
  "autoload": {
    "psr-4": {
      "App\\\\": "app/",
      "Core\\\\": "core/"
    }
  },
  "require": {
    "ext-pdo": "*"${withJWT ? ',\n    "firebase/php-jwt": "^6.10"' : ''}
  }
}`,

    index: `<?php
require_once __DIR__ . '/../vendor/autoload.php';

use Core\\Env;
use Core\\Router;

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

Env::load();
$router = new Router();
require __DIR__ . '/../app/Routes/web.php';
$router->dispatch();`,

    htaccess: `RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php [QSA,L]`,

    controller: `<?php
namespace App\\Controllers;

use Core\\Response;

class Controller
{
    protected $model;

    public function index()
    {
        Response::success([], 'Controlador base funcionando');
    }

    protected function getBody(): array
    {
        return json_decode(file_get_contents('php://input'), true) ?? [];
    }
}`,

    model: `<?php
namespace App\\Models;

use Core\\Database;
use PDO;

class Model
{
    protected $db;
    protected $table = '';

    public function __construct()
    {
        $this->db = Database::getConnection();
    }

    public function all(): array
    {
        return $this->db->query("SELECT * FROM {$this->table}")->fetchAll();
    }

    public function find($id)
    {
        $stmt = $this->db->prepare("SELECT * FROM {$this->table} WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetch();
    }

    public function create(array $data)
    {
        $cols = implode(', ', array_keys($data));
        $vals = implode(', ', array_fill(0, count($data), '?'));
        
        $stmt = $this->db->prepare("INSERT INTO {$this->table} ({$cols}) VALUES ({$vals})");
        $stmt->execute(array_values($data));
        
        return $this->find($this->db->lastInsertId());
    }

    public function update($id, array $data)
    {
        $sets = implode(', ', array_map(fn($k) => "{$k} = ?", array_keys($data)));
        
        $stmt = $this->db->prepare("UPDATE {$this->table} SET {$sets} WHERE id = ?");
        $stmt->execute([...array_values($data), $id]);
        
        return $this->find($id);
    }

    public function delete($id): bool
    {
        $stmt = $this->db->prepare("DELETE FROM {$this->table} WHERE id = ?");
        return $stmt->execute([$id]);
    }
}`,

    router: `<?php
namespace Core;

class Router
{
    private $routes = ['GET' => [], 'POST' => [], 'PUT' => [], 'DELETE' => []];

    public function get($path, $controller, $method)
    {
        $this->routes['GET'][$path] = [$controller, $method];
    }

    public function post($path, $controller, $method)
    {
        $this->routes['POST'][$path] = [$controller, $method];
    }

    public function put($path, $controller, $method)
    {
        $this->routes['PUT'][$path] = [$controller, $method];
    }

    public function delete($path, $controller, $method)
    {
        $this->routes['DELETE'][$path] = [$controller, $method];
    }

    public function dispatch()
    {
        $method = $_SERVER['REQUEST_METHOD'];
        $uri = rtrim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/') ?: '/';

        if (!isset($this->routes[$method])) {
            Response::error("Método no soportado: {$method}", 405);
        }

        foreach ($this->routes[$method] as $route => [$controller, $action]) {
            $pattern = '#^' . preg_replace('#\\{\\w+\\}#', '([\\w-]+)', rtrim($route, '/')) . '$#';

            if (preg_match($pattern, $uri, $matches)) {
                array_shift($matches);
                $this->execute($controller, $action, $matches);
                return;
            }
        }

        Response::error("Ruta no encontrada: {$uri}", 404);
    }

    private function execute($controller, $action, $params)
    {
        $class = "App\\\\Controllers\\\\{$controller}";

        if (!class_exists($class)) {
            Response::error("Controlador no encontrado: {$controller}", 404);
        }

        $instance = new $class();

        if (!method_exists($instance, $action)) {
            Response::error("Método no encontrado: {$action}", 404);
        }

        try {
            call_user_func_array([$instance, $action], $params);
        } catch (\\Exception $e) {
            Response::error('Error: ' . $e->getMessage(), 500);
        }
    }
}`,

    response: `<?php
namespace Core;

class Response
{
    public static function json($data, $code = 200)
    {
        http_response_code($code);
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }

    public static function success($data = [], $message = 'Operación exitosa', $code = 200)
    {
        self::json([
            'success' => true,
            'message' => $message,
            'data' => $data
        ], $code);
    }

    public static function error($message, $code = 400, $errors = null)
    {
        $response = ['success' => false, 'message' => $message];
        if ($errors !== null) $response['errors'] = $errors;
        self::json($response, $code);
    }
}`,

    env: `<?php
namespace Core;

class Env
{
    public static function load($path = __DIR__ . '/../.env')
    {
        if (!file_exists($path)) return;

        foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            if (str_starts_with(trim($line), '#') || !str_contains($line, '=')) continue;
            
            [$name, $value] = explode('=', $line, 2);
            putenv(trim($name) . '=' . trim($value));
        }
    }
}`,

    database: (dbType) => {
        if (dbType === 'mysql') {
            return `<?php
namespace Core;

use PDO;

class Database
{
    private static $conn = null;

    public static function getConnection()
    {
        if (self::$conn) return self::$conn;

        $host = getenv('DB_HOST') ?: 'localhost';
        $port = getenv('DB_PORT') ?: '3306';
        $db = getenv('DB_NAME') ?: 'mi_base';
        $user = getenv('DB_USER') ?: 'root';
        $pass = getenv('DB_PASS') ?: '';

        $dsn = "mysql:host={$host};port={$port};dbname={$db};charset=utf8mb4";

        try {
            self::$conn = new PDO($dsn, $user, $pass);
            self::$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            self::$conn->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
            return self::$conn;
        } catch (\\PDOException $e) {
            Response::error('Error de conexión: ' . $e->getMessage(), 500);
            exit;
        }
    }
}`;
        }

        return `<?php
namespace Core;

use PDO;

class Database
{
    private static $conn = null;

    public static function getConnection()
    {
        if (self::$conn) return self::$conn;

        $host = getenv('DB_HOST') ?: 'localhost';
        $port = getenv('DB_PORT') ?: '1433';
        $db = getenv('DB_NAME') ?: 'mi_base';
        $user = getenv('DB_USER') ?: 'sa';
        $pass = getenv('DB_PASS') ?: '';

        $dsn = "sqlsrv:Server={$host},{$port};Database={$db}";

        try {
            self::$conn = new PDO($dsn, $user, $pass);
            self::$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            self::$conn->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
            return self::$conn;
        } catch (\\PDOException $e) {
            Response::error('Error de conexión: ' . $e->getMessage(), 500);
            exit;
        }
    }
}`;
    },

    jwt: `<?php
namespace Core;

use Firebase\\JWT\\JWT as FirebaseJWT;
use Firebase\\JWT\\Key;

class JWT
{
    private static function getSecret(): string
    {
        return getenv('JWT_SECRET') ?: 'default_secret_change_in_production';
    }

    public static function encode(array $payload): string
    {
        $payload['iat'] = time();
        $payload['exp'] = time() + (int)(getenv('JWT_EXPIRATION') ?: 3600);
        
        return FirebaseJWT::encode($payload, self::getSecret(), 'HS256');
    }

    public static function decode(string $token): ?object
    {
        try {
            return FirebaseJWT::decode($token, new Key(self::getSecret(), 'HS256'));
        } catch (\\Exception $e) {
            return null;
        }
    }

    public static function getTokenFromHeader(): ?string
    {
        $headers = getallheaders();
        $auth = $headers['Authorization'] ?? $headers['authorization'] ?? '';
        
        if (preg_match('/Bearer\\s+(\\S+)/', $auth, $matches)) {
            return $matches[1];
        }
        
        return null;
    }

    public static function validate(): ?object
    {
        $token = self::getTokenFromHeader();
        
        if (!$token) {
            Response::error('Token no proporcionado', 401);
        }
        
        $payload = self::decode($token);
        
        if (!$payload) {
            Response::error('Token inválido o expirado', 401);
        }
        
        return $payload;
    }
}`,

    authMiddleware: `<?php
namespace Core;

class AuthMiddleware
{
    public static function handle(): object
    {
        return JWT::validate();
    }
}`,

    authController: `<?php
namespace App\\Controllers;

use App\\Models\\UserModel;
use Core\\Response;
use Core\\JWT;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->model = new UserModel();
    }

    public function register()
    {
        try {
            $body = $this->getBody();
            
            if (empty($body['email']) || empty($body['password'])) {
                Response::error('Email y contraseña son requeridos', 400);
            }

            // Verificar si el usuario ya existe
            $existing = $this->model->findByEmail($body['email']);
            if ($existing) {
                Response::error('El email ya está registrado', 409);
            }

            // Hash de la contraseña
            $body['password'] = password_hash($body['password'], PASSWORD_BCRYPT);
            
            $user = $this->model->create($body);
            unset($user['password']);

            $token = JWT::encode(['user_id' => $user['id'], 'email' => $user['email']]);

            Response::success([
                'user' => $user,
                'token' => $token
            ], 'Usuario registrado correctamente', 201);
        } catch (\\Exception $e) {
            Response::error('Error al registrar: ' . $e->getMessage(), 500);
        }
    }

    public function login()
    {
        try {
            $body = $this->getBody();
            
            if (empty($body['email']) || empty($body['password'])) {
                Response::error('Email y contraseña son requeridos', 400);
            }

            $user = $this->model->findByEmail($body['email']);
            
            if (!$user || !password_verify($body['password'], $user['password'])) {
                Response::error('Credenciales inválidas', 401);
            }

            unset($user['password']);

            $token = JWT::encode(['user_id' => $user['id'], 'email' => $user['email']]);

            Response::success([
                'user' => $user,
                'token' => $token
            ], 'Login exitoso');
        } catch (\\Exception $e) {
            Response::error('Error al hacer login: ' . $e->getMessage(), 500);
        }
    }

    public function me()
    {
        try {
            $payload = JWT::validate();
            
            $user = $this->model->find($payload->user_id);
            
            if (!$user) {
                Response::error('Usuario no encontrado', 404);
            }

            unset($user['password']);

            Response::success($user, 'Usuario autenticado');
        } catch (\\Exception $e) {
            Response::error('Error: ' . $e->getMessage(), 500);
        }
    }
}`,

    userModel: `<?php
namespace App\\Models;

class UserModel extends Model
{
    protected $table = 'users';

    public function findByEmail(string $email)
    {
        $stmt = $this->db->prepare("SELECT * FROM {$this->table} WHERE email = ?");
        $stmt->execute([$email]);
        return $stmt->fetch();
    }
}`,

    webRoutes: (withJWT) => {
        if (!withJWT) {
            return `<?php
$router->get('/', 'Controller', 'index');`;
        }

        return `<?php
use Core\\AuthMiddleware;

// Rutas públicas
$router->get('/', 'Controller', 'index');
$router->post('/auth/register', 'AuthController', 'register');
$router->post('/auth/login', 'AuthController', 'login');

// Rutas protegidas (ejemplo)
$router->get('/auth/me', 'AuthController', 'me');`;
    },

    envFile: (dbType, withJWT) => {
        const base = dbType === 'mysql'
            ? `DB_TYPE=mysql
DB_HOST=localhost
DB_PORT=3306
DB_NAME=mi_base
DB_USER=root
DB_PASS=`
            : `DB_TYPE=sqlsrv
DB_HOST=localhost
DB_PORT=1433
DB_NAME=mi_base
DB_USER=sa
DB_PASS=`;

        if (!withJWT) return base;

        return `${base}

# JWT Configuration
JWT_SECRET=your_secret_key_change_in_production_min_32_chars
JWT_EXPIRATION=3600`;
    },

    usersMigration: (dbType) => {
        if (dbType === 'mysql') {
            return `-- Tabla de usuarios para autenticación JWT
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Índice para búsquedas rápidas por email
CREATE INDEX idx_users_email ON users(email);`;
        }

        return `-- Tabla de usuarios para autenticación JWT
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='users' AND xtype='U')
CREATE TABLE users (
    id INT IDENTITY(1,1) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    created_at DATETIME DEFAULT GETDATE(),
    updated_at DATETIME DEFAULT GETDATE()
);

-- Índice para búsquedas rápidas por email
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_users_email')
CREATE INDEX idx_users_email ON users(email);`;
    },

    crudController: (name, model) => `<?php
namespace App\\Controllers;

use App\\Models\\${model};
use Core\\Response;

class ${name} extends Controller
{
    public function __construct()
    {
        $this->model = new ${model}();
    }

    public function index()
    {
        try {
            Response::success($this->model->all(), 'Registros obtenidos');
        } catch (\\Exception $e) {
            Response::error('Error: ' . $e->getMessage(), 500);
        }
    }

    public function show($id)
    {
        try {
            $data = $this->model->find($id);
            if (!$data) Response::error('No encontrado', 404);
            Response::success($data, 'Registro encontrado');
        } catch (\\Exception $e) {
            Response::error('Error: ' . $e->getMessage(), 500);
        }
    }

    public function store()
    {
        try {
            $body = $this->getBody();
            if (empty($body)) Response::error('Sin datos', 400);
            Response::success($this->model->create($body), 'Creado', 201);
        } catch (\\Exception $e) {
            Response::error('Error: ' . $e->getMessage(), 500);
        }
    }

    public function update($id)
    {
        try {
            $body = $this->getBody();
            if (empty($body)) Response::error('Sin datos', 400);
            if (!$this->model->find($id)) Response::error('No encontrado', 404);
            Response::success($this->model->update($id, $body), 'Actualizado');
        } catch (\\Exception $e) {
            Response::error('Error: ' . $e->getMessage(), 500);
        }
    }

    public function destroy($id)
    {
        try {
            if (!$this->model->find($id)) Response::error('No encontrado', 404);
            $this->model->delete($id);
            Response::success(null, 'Eliminado');
        } catch (\\Exception $e) {
            Response::error('Error: ' . $e->getMessage(), 500);
        }
    }
}`,

    crudModel: (name, table) => `<?php
namespace App\\Models;

class ${name} extends Model
{
    protected $table = '${table}';
}`,

    readme: (withJWT) => `# PHP Backend API

Backend PHP MVC con API REST JSON${withJWT ? ' y autenticación JWT' : ''}

## Instalación

\`\`\`bash
composer install
\`\`\`

## Configuración

Copia \`.env.example\` a \`.env\` y configura tus credenciales de base de datos${withJWT ? ' y JWT' : ''}.

${withJWT ? `## Base de datos

Ejecuta la migración SQL en tu base de datos:

\`\`\`bash
# Archivo: database/migrations/users.sql
\`\`\`

## Autenticación JWT

### Registro
\`\`\`bash
POST /auth/register
{
  "email": "user@example.com",
  "password": "password123",
  "name": "Usuario"
}
\`\`\`

### Login
\`\`\`bash
POST /auth/login
{
  "email": "user@example.com",
  "password": "password123"
}
\`\`\`

### Obtener usuario autenticado
\`\`\`bash
GET /auth/me
Headers:
  Authorization: Bearer {token}
\`\`\`

### Proteger rutas

En \`app/Routes/web.php\`:

\`\`\`php
use Core\\AuthMiddleware;

$router->get('/protected', 'MiController', 'metodo');
// Valida el token en el controlador con:
// $user = AuthMiddleware::handle();
\`\`\`
` : ''}

## Ejecutar servidor

\`\`\`bash
php -S localhost:8000 -t public
\`\`\`

## Comandos CLI

\`\`\`bash
php-init make:controller Producto
php-init make:model Producto
php-init make:crud Producto
php-init list:routes
\`\`\`
`
};

// ==============================
// Comandos
// ==============================

async function newProject(name) {
    const answers = await inquirer.prompt([
        {
            type: 'list',
            name: 'database',
            message: '¿Qué base de datos usarás?',
            choices: [
                { name: '🐬 MySQL', value: 'mysql' },
                { name: '🔷 SQL Server', value: 'sqlsrv' }
            ]
        },
        {
            type: 'confirm',
            name: 'withJWT',
            message: '¿Deseas autenticación JWT?',
            default: true
        },
        {
            type: 'input',
            name: 'dbHost',
            message: 'Host de la base de datos:',
            default: 'localhost'
        },
        {
            type: 'input',
            name: 'dbPort',
            message: 'Puerto de la base de datos:',
            default: (answers) => answers.database === 'mysql' ? '3306' : '1433'
        },
        {
            type: 'input',
            name: 'dbName',
            message: 'Nombre de la base de datos:',
            default: 'mi_base'
        },
        {
            type: 'input',
            name: 'dbUser',
            message: 'Usuario de la base de datos:',
            default: (answers) => answers.database === 'mysql' ? 'root' : 'sa'
        },
        {
            type: 'password',
            name: 'dbPass',
            message: 'Contraseña de la base de datos:',
            default: ''
        }
    ]);

    const base = path.join(process.cwd(), name);
    if (exists(base)) error(`"${name}" ya existe.`);

    const dirs = ['app/Controllers', 'app/Models', 'app/Routes', 'core', 'public'];
    if (answers.withJWT) dirs.push('database/migrations');

    dirs.forEach(dir => fs.ensureDirSync(path.join(base, dir)));

    let envContent = `DB_TYPE=${answers.database}
DB_HOST=${answers.dbHost}
DB_PORT=${answers.dbPort}
DB_NAME=${answers.dbName}
DB_USER=${answers.dbUser}
DB_PASS=${answers.dbPass}`;

    if (answers.withJWT) {
        envContent += `\n\nJWT_SECRET=${crypto.randomBytes(32).toString('hex')}
JWT_EXPIRATION=3600`;
    }

    const files = {
        'public/index.php': t.index,
        'public/.htaccess': t.htaccess,
        'app/Controllers/Controller.php': t.controller,
        'app/Models/Model.php': t.model,
        'app/Routes/web.php': t.webRoutes(answers.withJWT),
        'core/Router.php': t.router,
        'core/Database.php': t.database(answers.database),
        'core/Response.php': t.response,
        'core/Env.php': t.env,
        'composer.json': t.composer(answers.withJWT),
        '.env.example': t.envFile(answers.database, answers.withJWT),
        '.env': envContent,
        'README.md': t.readme(answers.withJWT)
    };

    if (answers.withJWT) {
        files['core/JWT.php'] = t.jwt;
        files['core/AuthMiddleware.php'] = t.authMiddleware;
        files['app/Controllers/AuthController.php'] = t.authController;
        files['app/Models/UserModel.php'] = t.userModel;
        files['database/migrations/users.sql'] = t.usersMigration(answers.database);
    }

    Object.entries(files).forEach(([file, content]) => write(base, file, content));

    success(`Proyecto "${name}" creado con ${answers.database === 'mysql' ? 'MySQL' : 'SQL Server'}${answers.withJWT ? ' + JWT' : ''}.`);
    console.log(`\n➡️  cd ${name}`);
    console.log(`   composer install`);
    if (answers.withJWT) {
        console.log(`   # Ejecuta database/migrations/users.sql en tu BD`);
    }
    console.log(`   php -S localhost:8000 -t public\n`);
}

async function makeController(name) {
    if (!inProject()) error('No estás en un proyecto.');

    const className = cap(name) + 'Controller';
    const file = path.join(process.cwd(), 'app/Controllers', `${className}.php`);

    if (exists(file)) return warn(`${className}.php ya existe.`);

    const model = cap(name) + 'Model';
    write(process.cwd(), `app/Controllers/${className}.php`, t.crudController(className, model));
    success(`Creado: app/Controllers/${className}.php`);
}

async function makeModel(name) {
    if (!inProject()) error('No estás en un proyecto.');

    const answers = await inquirer.prompt([
        {
            type: 'input',
            name: 'tableName',
            message: 'Nombre de la tabla en la BD:',
            default: name.toLowerCase() + 's'
        }
    ]);

    const className = cap(name) + 'Model';
    const file = path.join(process.cwd(), 'app/Models', `${className}.php`);

    if (exists(file)) return warn(`${className}.php ya existe.`);

    write(process.cwd(), `app/Models/${className}.php`, t.crudModel(className, answers.tableName));
    success(`Creado: app/Models/${className}.php`);
}

async function makeCrud(name) {
    if (!inProject()) error('No estás en un proyecto.');

    const answers = await inquirer.prompt([
        {
            type: 'input',
            name: 'tableName',
            message: 'Nombre de la tabla en la BD:',
            default: name.toLowerCase() + 's'
        }
    ]);

    const className = cap(name) + 'Model';
    const modelFile = path.join(process.cwd(), 'app/Models', `${className}.php`);

    if (!exists(modelFile)) {
        write(process.cwd(), `app/Models/${className}.php`, t.crudModel(className, answers.tableName));
        success(`Creado: app/Models/${className}.php`);
    }

    await makeController(name);

    const routesFile = path.join(process.cwd(), 'app/Routes/web.php');
    if (!exists(routesFile)) error('No se encontró web.php');

    const controller = cap(name) + 'Controller';
    const route = `/${name.toLowerCase()}s`;

    const routes = `
// CRUD ${cap(name)}
$router->get('${route}', '${controller}', 'index');
$router->get('${route}/{id}', '${controller}', 'show');
$router->post('${route}', '${controller}', 'store');
$router->post('${route}/{id}', '${controller}', 'update');
$router->post('${route}/{id}/delete', '${controller}', 'destroy');
`;

    fs.appendFileSync(routesFile, routes);
    success('CRUD completo creado.');
}

function listRoutes() {
    if (!inProject()) error('No estás en un proyecto.');

    const file = path.join(process.cwd(), 'app/Routes/web.php');
    if (!exists(file)) error('No se encontró web.php');

    const content = fs.readFileSync(file, 'utf8');
    const regex = /\$router->(get|post|put|delete)\s*\(\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*\)/g;

    console.log('\n📋 Rutas registradas:');
    console.log('-'.repeat(75));
    console.log('Método  | URI                  | Controlador          | Acción');
    console.log('-'.repeat(75));

    let match;
    while ((match = regex.exec(content)) !== null) {
        const [, method, uri, controller, action] = match;
        console.log(`${method.toUpperCase().padEnd(7)} | ${uri.padEnd(20)} | ${controller.padEnd(20)} | ${action}`);
    }
    console.log('-'.repeat(75) + '\n');
}

// ==============================
// CLI
// ==============================

program
    .command('new <nombre>')
    .description('Crea un nuevo proyecto PHP MVC')
    .action(newProject);

program
    .command('make:controller <nombre>')
    .description('Crea un controlador CRUD')
    .action(makeController);

program
    .command('make:model <nombre>')
    .description('Crea un modelo')
    .action(makeModel);

program
    .command('make:crud <nombre>')
    .description('Crea controlador, modelo y rutas CRUD')
    .action(makeCrud);

program
    .command('list:routes')
    .description('Lista todas las rutas')
    .action(listRoutes);

program.parse();