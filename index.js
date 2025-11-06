#!/usr/bin/env node
import { Command } from "commander";
import inquirer from "inquirer";
import fs from "fs-extra";
import path from "path";
import crypto from "crypto";
import { spawn } from "child_process";

const program = new Command();

program
    .name("php-init")
    .description("CLI para crear backend PHP MVC con API REST JSON")
    .version("1.0.0");

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
use Core\\RateLimit;
use Core\\Middleware;

header('Content-Type: application/json; charset=utf-8');

// CORS configurable por entorno
if (getenv('APP_ENV') === 'development') {
    header('Access-Control-Allow-Origin: *');
} else {
    $allowedOrigins = explode(',', getenv('ALLOWED_ORIGINS') ?: '');
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if (in_array($origin, $allowedOrigins)) {
        header("Access-Control-Allow-Origin: {$origin}");
    }
}

header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Simular PUT/DELETE desde POST
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['_method'])) {
    $_SERVER['REQUEST_METHOD'] = strtoupper($_POST['_method']);
}

Env::load();

// Rate limiting
$clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
RateLimit::check($clientIp);

// Registrar middlewares
Middleware::register('auth', 'Core\\AuthMiddleware::handle');

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

    protected function escapeIdentifier(string $identifier): string
    {
        return '\`' . str_replace('\`', '\`\`', $identifier) . '\`';
    }

    protected function getQuotedTable(): string
    {
        if (empty($this->table)) {
            throw new \\Exception('La propiedad $table no puede estar vacía en el modelo.');
        }
        return $this->escapeIdentifier($this->table);
    }

    public function all(): array
    {
        $table = $this->getQuotedTable();
        $stmt = $this->db->prepare("SELECT * FROM {$table}");
        $stmt->execute();
        return $stmt->fetchAll();
    }

    public function find($id)
    {
        $table = $this->getQuotedTable();
        $stmt = $this->db->prepare("SELECT * FROM {$table} WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetch();
    }

    public function create(array $data)
    {
        $table = $this->getQuotedTable();
        
        $escapedCols = array_map(
            fn($col) => $this->escapeIdentifier($col),
            array_keys($data)
        );
        
        $cols = implode(', ', $escapedCols);
        $vals = implode(', ', array_fill(0, count($data), '?'));
        
        $stmt = $this->db->prepare("INSERT INTO {$table} ({$cols}) VALUES ({$vals})");
        $stmt->execute(array_values($data));
        
        return $this->find($this->db->lastInsertId());
    }

    public function update($id, array $data)
    {
        $table = $this->getQuotedTable();
        
        $sets = implode(', ', array_map(
            fn($k) => $this->escapeIdentifier($k) . ' = ?',
            array_keys($data)
        ));
        
        $stmt = $this->db->prepare("UPDATE {$table} SET {$sets} WHERE id = ?");
        $stmt->execute([...array_values($data), $id]);
        
        return $this->find($id);
    }

    public function delete($id): bool
    {
        $table = $this->getQuotedTable();
        $stmt = $this->db->prepare("DELETE FROM {$table} WHERE id = ?");
        return $stmt->execute([$id]);
    }
}`,

    router: `<?php
namespace Core;

class Router
{
    private $routes = ['GET' => [], 'POST' => [], 'PUT' => [], 'DELETE' => []];
    private $compiledPatterns = [];

    public function get($path, $controller, $method)
    {
        $route = new Route($path, $controller, $method);
        $this->routes['GET'][$path] = $route;
        return $route;
    }

    public function post($path, $controller, $method)
    {
        $route = new Route($path, $controller, $method);
        $this->routes['POST'][$path] = $route;
        return $route;
    }

    public function put($path, $controller, $method)
    {
        $route = new Route($path, $controller, $method);
        $this->routes['PUT'][$path] = $route;
        return $route;
    }

    public function delete($path, $controller, $method)
    {
        $route = new Route($path, $controller, $method);
        $this->routes['DELETE'][$path] = $route;
        return $route;
    }

    public function dispatch()
    {
        $method = $_SERVER['REQUEST_METHOD'];
        $uri = rtrim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/') ?: '/';

        if (!isset($this->routes[$method])) {
            Logger::error("Método no soportado: {$method} en {$uri}");
            Response::error("Método no soportado: {$method}", 405);
        }

        foreach ($this->routes[$method] as $route => $routeObj) {
            if (!isset($this->compiledPatterns[$route])) {
                $this->compiledPatterns[$route] = '#^' . preg_replace('#\\{(\\w+)\\??\\}#', '([\\w-]*)', rtrim($route, '/')) . '$#';
            }

            $pattern = $this->compiledPatterns[$route];

            if (preg_match($pattern, $uri, $matches)) {
                array_shift($matches);
                $this->execute($routeObj, $matches);
                return;
            }
        }

        Logger::error("Ruta no encontrada: {$method} {$uri}");
        Response::error("Ruta no encontrada: {$uri}", 404);
    }

    private function execute(Route $route, array $params)
    {
        $controller = $route->getController();
        $action = $route->getAction();
        $middlewares = $route->getMiddlewares();
        
        $class = "App\\\\Controllers\\\\{$controller}";

        if (!class_exists($class)) {
            Logger::error("Controlador no encontrado: {$controller}");
            Response::error("Controlador no encontrado: {$controller}", 404);
        }

        $instance = new $class();

        if (!method_exists($instance, $action)) {
            Logger::error("Método no encontrado: {$action} en {$controller}");
            Response::error("Método no encontrado: {$action}", 404);
        }

        try {
            // Ejecutar middlewares
            Middleware::run($middlewares);
            
            // Sanitizar parámetros
            $sanitizedParams = array_map(function($param) {
                // Añadir validación de longitud máxima
                if (strlen($param) > 255) {
                    Logger::error("Parámetro de ruta excede longitud máxima");
                    Response::error('Parámetro inválido', 400);
                }
                return filter_var($param, FILTER_SANITIZE_SPECIAL_CHARS);
            }, $params);
            
            // Ejecutar controlador
            call_user_func_array([$instance, $action], $sanitizedParams);
        } catch (\\Exception $e) {
            Logger::error("Excepción en {$controller}::{$action}: " . $e->getMessage());
            Response::error('Error interno del servidor', 500);
        }
    }
}`,

    route: `<?php
namespace Core;

class Route
{
    private $path;
    private $controller;
    private $action;
    private $middlewares = [];

    public function __construct(string $path, string $controller, string $action)
    {
        $this->path = $path;
        $this->controller = $controller;
        $this->action = $action;
    }

    public function middleware(...$middlewares): self
    {
        $this->middlewares = array_merge($this->middlewares, $middlewares);
        return $this;
    }

    public function getPath(): string
    {
        return $this->path;
    }

    public function getController(): string
    {
        return $this->controller;
    }

    public function getAction(): string
    {
        return $this->action;
    }

    public function getMiddlewares(): array
    {
        return $this->middlewares;
    }
}`,

    middleware: `<?php
namespace Core;

class Middleware
{
    private static $middlewares = [];
    
    public static function register(string $name, string $handler): void
    {
        self::$middlewares[$name] = $handler;
    }
    
    public static function run(array $names): void
    {
        foreach ($names as $name) {
            if (!isset(self::$middlewares[$name])) {
                Logger::error("Middleware no encontrado: {$name}");
                Response::error("Middleware no encontrado: {$name}", 500);
            }
            
            $handler = self::$middlewares[$name];
            
            if (is_string($handler) && str_contains($handler, '::')) {
                [$class, $method] = explode('::', $handler);
                
                if (!class_exists($class)) {
                    Logger::error("Clase de middleware no encontrada: {$class}");
                    Response::error("Error de configuración de middleware", 500);
                }
                
                if (!method_exists($class, $method)) {
                    Logger::error("Método de middleware no encontrado: {$method} en {$class}");
                    Response::error("Error de configuración de middleware", 500);
                }
                
                call_user_func([$class, $method]);
            } elseif (is_callable($handler)) {
                call_user_func($handler);
            } else {
                Logger::error("Middleware inválido: {$name}");
                Response::error("Error de configuración de middleware", 500);
            }
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
    private static $cache = [];

    public static function load($path = __DIR__ . '/../.env')
    {
        if (!file_exists($path)) return;

        foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            if (str_starts_with(trim($line), '#') || !str_contains($line, '=')) continue;
            
            [$name, $value] = explode('=', $line, 2);
            $name = trim($name);
            $value = trim($value);
            putenv("{$name}={$value}");
            self::$cache[$name] = $value;
        }
    }

    public static function get($key, $default = null)
    {
        if (isset(self::$cache[$key])) {
            return self::$cache[$key];
        }

        $value = getenv($key);
        if ($value === false) {
            return $default;
        }

        self::$cache[$key] = $value;
        return $value;
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

        $host = Env::get('DB_HOST', 'localhost');
        $port = Env::get('DB_PORT', '3306');
        $db = Env::get('DB_NAME', 'mi_base');
        $user = Env::get('DB_USER', 'root');
        $pass = Env::get('DB_PASS', '');

        $dsn = "mysql:host={$host};port={$port};dbname={$db};charset=utf8mb4";

        try {
            self::$conn = new PDO($dsn, $user, $pass);
            self::$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            self::$conn->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
            return self::$conn;
        } catch (\\PDOException $e) {
            Logger::error('Error de conexión a la base de datos: ' . $e->getMessage());
            Response::error('Error de conexión a la base de datos', 500);
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

        $host = Env::get('DB_HOST', 'localhost');
        $port = Env::get('DB_PORT', '1433');
        $db = Env::get('DB_NAME', 'mi_base');
        $user = Env::get('DB_USER', 'sa');
        $pass = Env::get('DB_PASS', '');

        $dsn = "sqlsrv:Server={$host},{$port};Database={$db}";

        try {
            self::$conn = new PDO($dsn, $user, $pass);
            self::$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            self::$conn->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
            return self::$conn;
        } catch (\\PDOException $e) {
            Logger::error('Error de conexión a la base de datos: ' . $e->getMessage());
            Response::error('Error de conexión a la base de datos', 500);
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
        $secret = Env::get('JWT_SECRET');

        // En producción, el secret DEBE ser robusto.
        if (Env::get('APP_ENV') === 'production') {
            if (empty($secret)) {
                http_response_code(500);
                header('Content-Type: application/json');
                die(json_encode(['success' => false, 'message' => 'Error Crítico: JWT_SECRET no está definido en producción.']));
            }
            if (strlen($secret) < 32) {
                http_response_code(500);
                header('Content-Type: application/json');
                die(json_encode(['success' => false, 'message' => 'Error Crítico: JWT_SECRET debe tener al menos 32 caracteres en producción.']));
            }
            if ($secret === 'your_secret_key_change_in_production_min_32_chars') {
                http_response_code(500);
                header('Content-Type: application/json');
                die(json_encode(['success' => false, 'message' => 'Error Crítico: El JWT_SECRET por defecto está siendo usado en producción.']));
            }
        }

        // Para desarrollo, si no hay .env, usamos uno por defecto para que no falle.
        if (empty($secret)) {
            return 'unsafe_default_secret_for_dev_only';
        }

        return $secret;
    }

    public static function encode(array $payload, bool $isAccessToken = true): string
    {
        $payload['iat'] = time();
        $expiration = $isAccessToken 
            ? Env::get('JWT_ACCESS_TOKEN_EXPIRATION', 900)
            : Env::get('JWT_REFRESH_TOKEN_EXPIRATION', 2592000);
        $payload['exp'] = time() + (int)$expiration;
        $payload['jti'] = uniqid('jti_', true);
        
        return FirebaseJWT::encode($payload, self::getSecret(), 'HS256');
    }

    public static function decode(string $token): ?object
    {
        try {
            return FirebaseJWT::decode($token, new Key(self::getSecret(), 'HS256'));
        } catch (\\Exception $e) {
            Logger::error('Error al decodificar JWT: ' . $e->getMessage());
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

    public static function getPayload(): ?object
    {
        $token = self::getTokenFromHeader();
        if (!$token) return null;
        return self::decode($token);
    }

    public static function validate(): ?object
    {
        $token = self::getTokenFromHeader();
        
        if (!$token) {
            Logger::error('Token no proporcionado');
            Response::error('Token no proporcionado', 401);
        }
        
        $payload = self::decode($token);
        
        if (!$payload) {
            Logger::error('Token inválido o expirado');
            Response::error('Token inválido o expirado', 401);
        }
        
        return $payload;
    }
}`,

    authMiddleware: `<?php
namespace Core;

use App\\Models\\JwtDenylistModel;

class AuthMiddleware
{
    public static function handle(): void
    {
        $payload = JWT::validate();

        $denylist = new JwtDenylistModel();
        
        if ($payload->jti && $denylist->isDenied($payload->jti)) {
            Logger::error("Token revocado fue usado: jti={$payload->jti}");
            Response::error('Token ya no es válido', 401);
        }
        
        if (rand(1, 100) === 1) {
            try {
                $cleaned = $denylist->cleanupExpired();
                if ($cleaned > 0) {
                    Logger::info("Limpieza de denylist: {$cleaned} tokens eliminados");
                }
            } catch (\\Exception $e) {
                Logger::warning('Error al limpiar denylist', ['exception' => $e]);
            }
        }
        
        $_SERVER['AUTH_USER'] = $payload;
    }
    
    public static function getAuthUser(): ?object
    {
        return $_SERVER['AUTH_USER'] ?? null;
    }
}`,

    authController: `<?php
namespace App\\Controllers;

use App\\Models\\UserModel;
use App\\Models\\JwtDenylistModel;
use App\\Models\\RefreshTokenModel;
use Core\\Response;
use Core\\JWT;
use Core\\Validator;
use Core\\Logger;
use Core\\AuthMiddleware;

class AuthController extends Controller
{
    private $userModel;

    public function __construct()
    {
        $this->userModel = new UserModel();
    }

    public function register()
    {
        try {
            $body = $this->getBody();
            
            $errors = Validator::validate($body, [
                'email' => 'required|email',
                'password' => 'required|min:6',
                'name' => 'required|min:2'
            ]);
            
            if (!empty($errors)) {
                Response::error('Errores de validación', 422, $errors);
            }

            $existing = $this->userModel->findByEmail($body['email']);
            if ($existing) {
                Logger::warning('Intento de registro con email duplicado');
                Response::error('El email ya está registrado', 409);
            }

            $body['password'] = password_hash($body['password'], PASSWORD_BCRYPT);
            
            $user = $this->userModel->create($body);
            unset($user['password']);

            $token = JWT::encode(['user_id' => $user['id'], 'email' => $user['email']]);

            Logger::info('Usuario registrado exitosamente');

            Response::success([
                'user' => $user,
                'token' => $token
            ], 'Usuario registrado correctamente', 201);
        } catch (\\PDOException $e) {
            $errorId = uniqid('err_');
            Logger::error("Error de BD en registro [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error de base de datos. ID de error: {$errorId}", 500);
        } catch (\\Exception $e) {
            $errorId = uniqid('err_');
            Logger::error("Error al registrar [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error al registrar usuario. ID: {$errorId}", 500);
        }
    }

    public function login()
    {
        try {
            $body = $this->getBody();
            $errors = Validator::validate($body, ['email' => 'required|email', 'password' => 'required']);
            if (!empty($errors)) Response::error('Errores de validación', 422, $errors);

            $user = $this->userModel->findByEmail($body['email']);
            if (!$user || !password_verify($body['password'], $user['password'])) {
                Logger::warning('Intento de login fallido');
                Response::error('Credenciales inválidas', 401);
            }

            unset($user['password']);

            $accessToken = JWT::encode(['user_id' => $user['id'], 'email' => $user['email']]);
            
            $refreshTokenModel = new RefreshTokenModel();
            $refreshTokenValidity = Env::get('JWT_REFRESH_TOKEN_EXPIRATION', 2592000);
            $refreshToken = $refreshTokenModel->createForUser($user['id'], $refreshTokenValidity);

            Logger::info('Login exitoso');

            Response::success([
                'user' => $user,
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken
            ], 'Login exitoso');
        } catch (\\PDOException $e) {
            $errorId = uniqid('err_');
            Logger::error("Error de BD en login [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error de base de datos. ID de error: {$errorId}", 500);
        } catch (\\Exception $e) {
            $errorId = uniqid('err_');
            Logger::error("Error al hacer login [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error al hacer login. ID: {$errorId}", 500);
        }
    }

    public function refresh()
    {
        try {
            $body = $this->getBody();
            $refreshToken = $body['refresh_token'] ?? '';
            if (empty($refreshToken)) Response::error('Refresh token no proporcionado', 400);

            $refreshTokenModel = new RefreshTokenModel();
            $tokenData = $refreshTokenModel->findByToken($refreshToken);

            if (!$tokenData || strtotime($tokenData['expires_at']) < time()) {
                Response::error('Refresh token inválido o expirado', 401);
            }

            $refreshTokenModel->delete($tokenData['id']);

            $user = $this->userModel->find($tokenData['user_id']);
            if (!$user) Response::error('Usuario no encontrado', 404);

            $newAccessToken = JWT::encode(['user_id' => $user['id'], 'email' => $user['email']]);
            $newRefreshTokenValidity = Env::get('JWT_REFRESH_TOKEN_EXPIRATION', 2592000);
            $newRefreshToken = $refreshTokenModel->createForUser($user['id'], $newRefreshTokenValidity);

            Response::success([
                'access_token' => $newAccessToken,
                'refresh_token' => $newRefreshToken
            ], 'Tokens actualizados');

        } catch (\\PDOException $e) {
            $errorId = uniqid('err_');
            Logger::error("Error de BD al refrescar token [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error de base de datos. ID de error: {$errorId}", 500);
        } catch (\\Exception $e) {
            $errorId = uniqid('err_');
            Logger::error("Error al refrescar token [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error al refrescar token. ID: {$errorId}", 500);
        }
    }

    public function logout()
    {
        try {
            $payload = JWT::getPayload();
            if ($payload && isset($payload->jti) && isset($payload->exp)) {
                (new JwtDenylistModel())->deny($payload->jti, $payload->exp);
                (new RefreshTokenModel())->deleteAllForUser($payload->user_id);
            }
            Response::success(null, 'Sesión cerrada correctamente');
        } catch (\\PDOException $e) {
            $errorId = uniqid('err_');
            Logger::error("Error de BD en logout [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error de base de datos. ID de error: {$errorId}", 500);
        } catch (\\Exception $e) {
            $errorId = uniqid('err_');
            Logger::error("Error al cerrar sesión [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error al cerrar sesión. ID: {$errorId}", 500);
        }
    }

    public function me()
    {
        try {
            $payload = AuthMiddleware::getAuthUser();
            
            $user = $this->userModel->find($payload->user_id);
            
            if (!$user) {
                Response::error('Usuario no encontrado', 404);
            }

            unset($user['password']);

            Response::success($user, 'Usuario autenticado');
        } catch (\\PDOException $e) {
            $errorId = uniqid('err_');
            Logger::error("Error de BD en /auth/me [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error de base de datos. ID de error: {$errorId}", 500);
        } catch (\\Exception $e) {
            $errorId = uniqid('err_');
            Logger::error("Error en /auth/me [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error al obtener usuario. ID: {$errorId}", 500);
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
        $stmt = $this->db->prepare("SELECT * FROM {$this->getQuotedTable()} WHERE email = ?");
        $stmt->execute([$email]);
        return $stmt->fetch();
    }
}`,

    validator: `<?php
namespace Core;

class Validator
{
    public static function validate(array $data, array $rules): array
    {
        $errors = [];
        
        foreach ($rules as $field => $ruleset) {
            $rulesArray = explode('|', $ruleset);
            
            foreach ($rulesArray as $rule) {
                if ($rule === 'required' && empty($data[$field])) {
                    $errors[$field][] = "El campo {$field} es requerido";
                    continue;
                }
                
                if (str_starts_with($rule, 'min:') && isset($data[$field])) {
                    $min = (int)substr($rule, 4);
                    if (strlen($data[$field]) < $min) {
                        $errors[$field][] = "El campo {$field} debe tener al menos {$min} caracteres";
                    }
                }
                
                if (str_starts_with($rule, 'max:') && isset($data[$field])) {
                    $max = (int)substr($rule, 4);
                    if (strlen($data[$field]) > $max) {
                        $errors[$field][] = "El campo {$field} no puede tener más de {$max} caracteres";
                    }
                }
                
                if ($rule === 'email' && isset($data[$field])) {
                    if (!filter_var($data[$field], FILTER_VALIDATE_EMAIL)) {
                        $errors[$field][] = "El campo {$field} debe ser un email válido";
                    }
                }
                
                if ($rule === 'numeric' && isset($data[$field])) {
                    if (!is_numeric($data[$field])) {
                        $errors[$field][] = "El campo {$field} debe ser numérico";
                    }
                }
                
                if ($rule === 'alpha' && isset($data[$field])) {
                    if (!ctype_alpha($data[$field])) {
                        $errors[$field][] = "El campo {$field} solo debe contener letras";
                    }
                }
            }
        }

        return $errors;
    }
}`,

    logger: `<?php
namespace Core;

class Logger
{
    private static $logDir = __DIR__ . '/../logs';
    private static $retentionDays = 7;

    private static function sanitizeContext(array $context): array
    {
        $sensitiveKeys = ['password', 'token', 'secret', 'api_key', 'credit_card', 'ssn', 'authorization'];
        
        array_walk_recursive($context, function(&$value, $key) use ($sensitiveKeys) {
            if (in_array(strtolower($key), $sensitiveKeys, true)) {
                $value = '[REDACTED]';
            }
        });
        
        return $context;
    }

    private static function write(string $level, string $message, array $context = []): void
    {
        if (!is_dir(self::$logDir)) {
            mkdir(self::$logDir, 0755, true);
        }

        $logFile = self::$logDir . '/app-' . date('Y-m-d') . '.log';

        if (!file_exists($logFile)) {
            self::cleanupOldLogs();
        }

        $entry = [
            'timestamp' => date('c'),
            'level' => $level,
            'message' => $message,
        ];

        if (!empty($context)) {
            $context = self::sanitizeContext($context);
            
            if (isset($context['exception']) && $context['exception'] instanceof \\Throwable) {
                $e = $context['exception'];
                $context['exception'] = [
                    'class' => get_class($e),
                    'message' => $e->getMessage(),
                    'file' => $e->getFile() . ':' . $e->getLine(),
                    'trace' => $e->getTraceAsString(),
                ];
            }
            $entry['context'] = $context;
        }

        $jsonEntry = json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        file_put_contents($logFile, $jsonEntry . "\\n", FILE_APPEND);
    }

    private static function cleanupOldLogs(): void
    {
        $cutoff = strtotime('-' . self::$retentionDays . ' days');

        foreach (glob(self::$logDir . '/app-*.log') as $file) {
            if (preg_match('/app-(\\d{4}-\\d{2}-\\d{2})\\.log$/', $file, $matches)) {
                $fileDate = strtotime($matches[1]);
                if ($fileDate < $cutoff) {
                    unlink($file);
                }
            }
        }
    }

    public static function error(string $message, array $context = []): void
    {
        self::write('ERROR', $message, $context);
    }

    public static function warning(string $message, array $context = []): void
    {
        self::write('WARNING', $message, $context);
    }

    public static function info(string $message, array $context = []): void
    {
        self::write('INFO', $message, $context);
    }
}`,

    rateLimit: `<?php
namespace Core;

class RateLimit
{
    private static $storageFile = __DIR__ . '/../logs/ratelimit.json';
    private static $lockFile = __DIR__ . '/../logs/ratelimit.lock';
    
    private static function withLock(callable $callback)
    {
        $logDir = dirname(self::$lockFile);
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
        
        $lock = fopen(self::$lockFile, 'c');
        if (!flock($lock, LOCK_EX)) {
            throw new \\Exception('No se pudo obtener el lock');
        }
        
        try {
            return $callback();
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
    
    private static function getStorage(): array
    {
        if (!file_exists(self::$storageFile)) {
            return [];
        }
        
        $content = file_get_contents(self::$storageFile);
        return json_decode($content, true) ?? [];
    }
    
    private static function saveStorage(array $data): void
    {
        $logDir = dirname(self::$storageFile);
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
        file_put_contents(self::$storageFile, json_encode($data));
    }
    
    private static function cleanupOldEntries(int $window): void
    {
        $storage = self::getStorage();
        $now = time();
        
        foreach ($storage as $key => $data) {
            $allExpired = empty(array_filter(
                $data['requests'],
                fn($time) => $now - $time < $window
            ));
            
            if ($allExpired && $data['blocked_until'] < $now) {
                unset($storage[$key]);
            }
        }
        
        self::saveStorage($storage);
    }
    
    public static function check(string $ip, int $limit = 100, int $window = 60): bool
    {
        return self::withLock(function() use ($ip, $limit, $window) {
            $storage = self::getStorage();
            $now = time();
            $key = "ip_{$ip}";
            
            if (!isset($storage[$key])) {
                $storage[$key] = ['requests' => [], 'blocked_until' => 0];
            }
            
            if ($storage[$key]['blocked_until'] > $now) {
                Logger::warning("IP bloqueada por rate limit: {$ip}");
                Response::error('Demasiadas peticiones. Intenta de nuevo más tarde.', 429);
            }
            
            $storage[$key]['requests'] = array_filter(
                $storage[$key]['requests'],
                fn($time) => $now - $time < $window
            );
            
            if (count($storage[$key]['requests']) >= $limit) {
                $storage[$key]['blocked_until'] = $now + $window;
                self::saveStorage($storage);
                Logger::warning("Rate limit excedido para IP: {$ip}");
                Response::error('Demasiadas peticiones. Intenta de nuevo más tarde.', 429);
            }
            
            $storage[$key]['requests'][] = $now;
            self::saveStorage($storage);
            
            if (rand(1, 100) === 1) {
                self::cleanupOldEntries($window);
            }
            
            return true;
        });
    }
}`,

    webRoutes: (withJWT) => {
        if (!withJWT) {
            return `<?php
$router->get('/', 'Controller', 'index');
$router->get('/health', 'HealthController', 'status');`;
        }

        return `<?php
// Rutas públicas
$router->get('/', 'Controller', 'index');
$router->get('/health', 'HealthController', 'status');
$router->post('/auth/register', 'AuthController', 'register');
$router->post('/auth/login', 'AuthController', 'login');
$router->post('/auth/refresh', 'AuthController', 'refresh');
$router->post('/auth/logout', 'AuthController', 'logout')->middleware('auth');

// Rutas protegidas con middleware
$router->get('/auth/me', 'AuthController', 'me')->middleware('auth');

// Ejemplo de múltiples middlewares
// $router->get('/admin/dashboard', 'AdminController', 'index')->middleware('auth', 'admin');`;
    },

    envFile: (dbType, withJWT, env = 'development') => {
        const baseEnv = `APP_ENV=${env}

# Database
`;
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

        if (!withJWT) return baseEnv + base;

        return `${baseEnv}${base}

# JWT Configuration
JWT_SECRET=your_secret_key_change_in_production_min_32_chars
JWT_ACCESS_TOKEN_EXPIRATION=900
JWT_REFRESH_TOKEN_EXPIRATION=2592000

# CORS (en producción, define los orígenes permitidos)
# ALLOWED_ORIGINS=https://tudominio.com,https://otrodominio.com`;
    },

    healthController: `<?php
namespace App\\Controllers;

use Core\\Response;
use Core\\Database;

class HealthController extends Controller
{
    public function status()
    {
        $status = [
            'status' => 'healthy',
            'timestamp' => time(),
            'services' => [
                'database' => $this->checkDatabase()
            ]
        ];
        
        Response::success($status);
    }
    
    private function checkDatabase(): string
    {
        try {
            Database::getConnection()->query('SELECT 1');
            return 'connected';
        } catch (\\Exception $e) {
            return 'disconnected';
        }
    }
}`,

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

    jwtDenylistMigration: (dbType) => {
        if (dbType === 'mysql') {
            return `-- Tabla para la lista negra de JWT revocados
CREATE TABLE IF NOT EXISTS jwt_denylist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    jti VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Índice para búsquedas rápidas de tokens revocados
CREATE INDEX idx_jwt_denylist_jti ON jwt_denylist(jti);
`;
        }

        return `-- Tabla para la lista negra de JWT revocados
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='jwt_denylist' AND xtype='U')
CREATE TABLE jwt_denylist (
    id INT IDENTITY(1,1) PRIMARY KEY,
    jti VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT GETDATE()
);

-- Índice para búsquedas rápidas de tokens revocados
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_jwt_denylist_jti')
CREATE INDEX idx_jwt_denylist_jti ON jwt_denylist(jti);
`;
    },

    refreshTokenMigration: (dbType) => {
        if (dbType === 'mysql') {
            return `-- Tabla para almacenar refresh tokens
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
`;
        }

        return `-- Tabla para almacenar refresh tokens
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='refresh_tokens' AND xtype='U')
CREATE TABLE refresh_tokens (
    id INT IDENTITY(1,1) PRIMARY KEY,
    user_id INT NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT GETDATE(),
    CONSTRAINT FK_refresh_tokens_users FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_refresh_tokens_user_id')
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
`;
    },

    refreshTokenModel: `<?php
namespace App\\Models;

class RefreshTokenModel extends Model
{
    protected $table = 'refresh_tokens';

    public function createForUser(int $userId, int $validity): string
    {
        $token = bin2hex(random_bytes(32));
        $expires_at = date('Y-m-d H:i:s', time() + $validity);

        $this->create([
            'user_id' => $userId,
            'token_hash' => hash('sha256', $token),
            'expires_at' => $expires_at
        ]);

        return $token;
    }

    public function findByToken(string $token)
    {
        $hash = hash('sha256', $token);
        $stmt = $this->db->prepare("SELECT * FROM {$this->getQuotedTable()} WHERE token_hash = ?");
        $stmt->execute([$hash]);
        return $stmt->fetch();
    }

    public function deleteAllForUser(int $userId): bool
    {
        $stmt = $this->db->prepare("DELETE FROM {$this->getQuotedTable()} WHERE user_id = ?");
        return $stmt->execute([$userId]);
    }
}`,

    jwtDenylistModel: `<?php
namespace App\\Models;

class JwtDenylistModel extends Model
{
    protected $table = 'jwt_denylist';

    public function deny(string $jti, int $expires_at): bool
    {
        $data = [
            'jti' => $jti,
            'expires_at' => date('Y-m-d H:i:s', $expires_at)
        ];
        return (bool)$this->create($data);
    }

    public function isDenied(string $jti): bool
    {
        $stmt = $this->db->prepare("SELECT 1 FROM {$this->getQuotedTable()} WHERE jti = ?");
        $stmt->execute([$jti]);
        return (bool)$stmt->fetch();
    }

    public function cleanupExpired(): int
    {
        $stmt = $this->db->prepare("DELETE FROM {$this->getQuotedTable()} WHERE expires_at < NOW()");
        $stmt->execute();
        return $stmt->rowCount();
    }
}`,

    customMiddleware: (name) => `<?php
namespace Core;

class ${name}
{
    /**
     * Maneja la lógica del middleware ${name}
     * 
     * @return void
     */
    public static function handle(): void
    {
        // TODO: Implementa la lógica de tu middleware aquí
        
        // Ejemplo: Verificar un header personalizado
        // $customHeader = $_SERVER['HTTP_X_CUSTOM_HEADER'] ?? null;
        // if (!$customHeader) {
        //     Logger::error('Header personalizado no encontrado');
        //     Response::error('Header personalizado requerido', 403);
        // }
        
        // Ejemplo: Verificar permisos de usuario
        // $user = AuthMiddleware::getAuthUser();
        // if (!$user || !isset($user->role) || $user->role !== 'admin') {
        //     Logger::error('Acceso denegado: usuario no tiene permisos suficientes');
        //     Response::error('Acceso denegado', 403);
        // }
        
        // Si todo está bien, el middleware permite continuar
        Logger::info('Middleware ${name} ejecutado correctamente');
    }
}`,

    crudController: (name, model) => `<?php
namespace App\\Controllers;

use App\\Models\\${model};
use Core\\Response;
use Core\\Logger;

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
        } catch (\\PDOException $e) {
            $errorId = uniqid('err_');
            Logger::error("Error de BD en {$name}::index [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error de base de datos. ID de error: {$errorId}", 500);
        } catch (\\Exception $e) {
            $errorId = uniqid('err_');
            Logger::error("Error en {$name}::index [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error inesperado. ID de error: {$errorId}", 500);
        }
    }

    public function show($id)
    {
        try {
            $data = $this->model->find($id);
            if (!$data) Response::error('No encontrado', 404);
            Response::success($data, 'Registro encontrado');
        } catch (\\PDOException $e) {
            $errorId = uniqid('err_');
            Logger::error("Error de BD en {$name}::show [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error de base de datos. ID de error: {$errorId}", 500);
        } catch (\\Exception $e) {
            $errorId = uniqid('err_');
            Logger::error("Error en {$name}::show [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error inesperado. ID de error: {$errorId}", 500);
        }
    }

    public function store()
    {
        try {
            $body = $this->getBody();
            if (empty($body)) Response::error('Sin datos para crear', 400);
            $newItem = $this->model->create($body);
            Response::success($newItem, 'Registro creado', 201);
        } catch (\\PDOException $e) {
            $errorId = uniqid('err_');
            Logger::error("Error de BD en {$name}::store [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error de base de datos. ID de error: {$errorId}", 500);
        } catch (\\Exception $e) {
            $errorId = uniqid('err_');
            Logger::error("Error en {$name}::store [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error inesperado. ID de error: {$errorId}", 500);
        }
    }

    public function update($id)
    {
        try {
            $body = $this->getBody();
            if (empty($body)) Response::error('Sin datos para actualizar', 400);
            if (!$this->model->find($id)) Response::error('Registro no encontrado', 404);
            $updatedItem = $this->model->update($id, $body);
            Response::success($updatedItem, 'Registro actualizado');
        } catch (\\PDOException $e) {
            $errorId = uniqid('err_');
            Logger::error("Error de BD en {$name}::update [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error de base de datos. ID de error: {$errorId}", 500);
        } catch (\\Exception $e) {
            $errorId = uniqid('err_');
            Logger::error("Error en {$name}::update [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error inesperado. ID de error: {$errorId}", 500);
        }
    }

    public function destroy($id)
    {
        try {
            if (!$this->model->find($id)) Response::error('Registro no encontrado', 404);
            $this->model->delete($id);
            Response::success(null, 'Registro eliminado');
        } catch (\\PDOException $e) {
            $errorId = uniqid('err_');
            Logger::error("Error de BD en {$name}::destroy [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error de base de datos. ID de error: {$errorId}", 500);
        } catch (\\Exception $e) {
            $errorId = uniqid('err_');
            Logger::error("Error en {$name}::destroy [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error inesperado. ID de error: {$errorId}", 500);
        }
    }
}`,

    crudModel: (name, table) => `<?php
namespace App\\Models;

class ${name} extends Model
{
    protected $table = '${table}';
}`,

    testTemplate: (name) => `<?php
use PHPUnit\\Framework\\TestCase;

class ${cap(name)}Test extends TestCase
{
    public function testExample()
    {
        $this->assertTrue(true);
    }
}`,

    gitignore: `.env
.env.*.local
/vendor/
/node_modules/
/logs/*.log
/logs/ratelimit.json
/logs/ratelimit.lock
*.log
.DS_Store
Thumbs.db`,

    readme: (withJWT) => `# PHP Backend API

Backend PHP MVC con API REST JSON${withJWT ? ' y autenticación JWT' : ''}

## Instalación

\`\`\`bash
composer install
\`\`\`

## Configuración

Copia \`.env.example\` a \`.env\` y configura tus credenciales de base de datos${withJWT ? ' y JWT' : ''}.

${withJWT ? `## Base de datos

Ejecuta las migraciones SQL en tu base de datos:

\`\`\`bash
# Archivos en: database/migrations/
# - users.sql
# - jwt_denylist.sql
# - refresh_tokens.sql
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

### Refrescar Token
\`\`\`bash
POST /auth/refresh
{
  "refresh_token": "your_refresh_token_here"
}
\`\`\`

### Cerrar Sesión
\`\`\`bash
POST /auth/logout
Headers:
  Authorization: Bearer {access_token}
\`\`\`

### Obtener usuario autenticado
\`\`\`bash
GET /auth/me
Headers:
  Authorization: Bearer {access_token}
\`\`\`

## Sistema de Middleware

Las rutas pueden protegerse con middleware de forma elegante:

\`\`\`php
// En app/Routes/web.php

// Ruta pública
$router->get('/public', 'PublicController', 'index');

// Ruta protegida con autenticación
$router->get('/profile', 'ProfileController', 'show')->middleware('auth');

// Múltiples middlewares
$router->get('/admin/users', 'AdminController', 'users')->middleware('auth', 'admin');
\`\`\`

### Crear middleware personalizado

1. Genera el middleware con la CLI:

\`\`\`bash
php-init make:middleware Admin
\`\`\`

2. Implementa la lógica en \`core/AdminMiddleware.php\`:

\`\`\`php
<?php
namespace Core;

class AdminMiddleware
{
    public static function handle(): void
    {
        $user = AuthMiddleware::getAuthUser();
        
        if (!$user || $user->role !== 'admin') {
            Logger::error('Acceso denegado: usuario no es admin');
            Response::error('Acceso denegado', 403);
        }
    }
}
\`\`\`

3. Regístralo en \`public/index.php\`:

\`\`\`php
Middleware::register('admin', 'Core\\\\AdminMiddleware::handle');
\`\`\`

4. Úsalo en tus rutas:

\`\`\`php
$router->delete('/users/{id}', 'UserController', 'destroy')->middleware('auth', 'admin');
\`\`\`

### Acceder al usuario autenticado

En cualquier controlador protegido con el middleware \`auth\`:

\`\`\`php
use Core\\AuthMiddleware;

public function myMethod()
{
    $user = AuthMiddleware::getAuthUser();
    // $user contiene: { user_id, email, jti, iat, exp }
}
\`\`\`
` : ''}

## Health Check

\`\`\`bash
GET /health
\`\`\`

## Ejecutar servidor

\`\`\`bash
php-init server
# o
php -S localhost:8000 -t public
\`\`\`

## Comandos CLI

\`\`\`bash
# Crear proyecto
php-init new mi-proyecto

# Generar código
php-init make:controller Producto
php-init make:model Producto
php-init make:middleware Admin
php-init make:crud Producto
php-init make:test Producto

# Utilidades
php-init list:routes
php-init server
\`\`\`

## Características

- ✅ **Arquitectura MVC limpia** con separación de responsabilidades
- ✅ **Sistema de middleware robusto** para protección de rutas
- ✅ **Generación de middlewares personalizados** con CLI
- ✅ **Validación de datos** con reglas personalizables
- ✅ **Rate limiting mejorado** con file locks y limpieza automática
- ✅ **Logging estructurado** con rotación automática y sanitización de datos sensibles
- ✅ **Manejo de errores robusto** con IDs únicos para debugging
- ✅ **Sanitización** automática de parámetros de ruta
- ✅ **Protección contra SQL Injection** con escapado de identificadores y prepared statements
${withJWT ? '- ✅ **Autenticación JWT** con refresh tokens y revocación' : ''}
- ✅ **CORS** configurado para desarrollo y producción
- ✅ **PSR-4 autoloading** con Composer
- ✅ **Health checks** automáticos
- ✅ **Múltiples entornos** de configuración

## Mejoras de Seguridad

### SQL Injection Prevention
Todos los nombres de tablas y columnas se escapan automáticamente usando el método \`escapeIdentifier()\` y se usan prepared statements.

### JWT Security
${withJWT ? `- Validación estricta de JWT_SECRET en producción
- Refresh tokens con rotación automática
- Revocación de tokens (denylist) con limpieza automática
- JWT ID único (jti) para rastreo individual` : 'No aplicable (JWT no habilitado)'}

### Logging Seguro
Los datos sensibles (passwords, tokens, secrets) se sanitizan automáticamente antes de escribirse en logs.

### Rate Limiting
- File locking para prevenir race conditions
- Limpieza automática de entradas antiguas
- Configurable por IP

## Estructura del proyecto

\`\`\`
├── app/
│   ├── Controllers/     # Controladores de la aplicación
│   ├── Models/          # Modelos de datos
│   └── Routes/          # Definición de rutas
├── core/                # Núcleo del framework
│   ├── Router.php       # Sistema de enrutamiento
│   ├── Route.php        # Clase de ruta individual
│   ├── Middleware.php   # Gestor de middlewares
│   ├── Response.php     # Respuestas JSON estandarizadas
│   ├── Validator.php    # Validación de datos
│   ├── Logger.php       # Sistema de logs con sanitización
│   ├── RateLimit.php    # Control de tasa de peticiones mejorado
│   ├── Database.php     # Conexión a BD
│   └── Env.php          # Carga de variables de entorno
├── database/
│   └── migrations/      # Migraciones SQL
├── logs/                # Archivos de log (rotación automática)
├── public/              # Directorio público
│   ├── index.php        # Punto de entrada
│   └── .htaccess        # Reglas de reescritura
├── tests/               # Tests automatizados
├── .env                 # Variables de entorno
├── .env.example         # Ejemplo de variables de entorno
├── .gitignore          # Archivos ignorados por Git
└── composer.json        # Dependencias PHP
\`\`\`

## Validación de datos

\`\`\`php
use Core\\Validator;

$errors = Validator::validate($data, [
    'email' => 'required|email',
    'password' => 'required|min:6|max:50',
    'age' => 'numeric',
    'username' => 'required|alpha'
]);

if (!empty($errors)) {
    Response::error('Errores de validación', 422, $errors);
}
\`\`\`

Reglas disponibles:
- \`required\`: Campo obligatorio
- \`email\`: Validar formato de email
- \`min:n\`: Longitud mínima
- \`max:n\`: Longitud máxima
- \`numeric\`: Solo números
- \`alpha\`: Solo letras

## Logging

\`\`\`php
use Core\\Logger;

Logger::info('Información general');
Logger::warning('Advertencia');
Logger::error('Error crítico', ['exception' => $e]);
\`\`\`

Los logs:
- Se guardan en formato JSON en \`logs/app-YYYY-MM-DD.log\`
- Se rotan automáticamente (retención de 7 días)
- Sanitizan datos sensibles automáticamente

## Rate Limiting

Por defecto: 100 peticiones por minuto por IP.

Para personalizar, edita \`public/index.php\`:

\`\`\`php
RateLimit::check($clientIp, 50, 120); // 50 peticiones cada 2 minutos
\`\`\`

Características:
- File locking para prevenir race conditions
- Limpieza automática de IPs antiguas (1% de probabilidad por request)
- Almacenamiento en JSON con locks

## Recomendaciones para Producción

1. **Cambiar JWT_SECRET**: Genera uno seguro de 32+ caracteres
2. **Configurar APP_ENV=production**: Activa validaciones estrictas
3. **Rate Limiting con Redis**: Para mejor performance en múltiples servidores
4. **HTTPS**: Siempre usa SSL/TLS en producción
5. **Logs externos**: Integra con Sentry, Datadog, etc.
6. **Backups**: Configura backups automáticos de la base de datos

## Soporte

Para más información o reportar issues, visita el repositorio del proyecto.
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

    const dirs = ['app/Controllers', 'app/Models', 'app/Routes', 'core', 'public', 'logs', 'tests'];
    if (answers.withJWT) dirs.push('database/migrations');

    dirs.forEach(dir => fs.ensureDirSync(path.join(base, dir)));

    // Generar múltiples archivos .env
    const envFiles = {
        '.env.example': t.envFile(answers.database, answers.withJWT, 'development'),
        '.env.dev': t.envFile(answers.database, answers.withJWT, 'development'),
        '.env.test': t.envFile(answers.database, answers.withJWT, 'testing'),
        '.env.prod': t.envFile(answers.database, answers.withJWT, 'production')
    };

    let envContent = `APP_ENV=development

DB_TYPE=${answers.database}
DB_HOST=${answers.dbHost}
DB_PORT=${answers.dbPort}
DB_NAME=${answers.dbName}
DB_USER=${answers.dbUser}
DB_PASS=${answers.dbPass}`;

    if (answers.withJWT) {
        envContent += `

JWT_SECRET=${crypto.randomBytes(64).toString('hex')}
JWT_ACCESS_TOKEN_EXPIRATION=900
JWT_REFRESH_TOKEN_EXPIRATION=2592000

# CORS (en producción, define los orígenes permitidos)
# ALLOWED_ORIGINS=https://tudominio.com,https://otrodominio.com`;
    }

    const files = {
        'public/index.php': t.index,
        'public/.htaccess': t.htaccess,
        'app/Controllers/Controller.php': t.controller,
        'app/Controllers/HealthController.php': t.healthController,
        'app/Models/Model.php': t.model,
        'app/Routes/web.php': t.webRoutes(answers.withJWT),
        'core/Router.php': t.router,
        'core/Route.php': t.route,
        'core/Middleware.php': t.middleware,
        'core/Database.php': t.database(answers.database),
        'core/Response.php': t.response,
        'core/Env.php': t.env,
        'core/Validator.php': t.validator,
        'core/Logger.php': t.logger,
        'core/RateLimit.php': t.rateLimit,
        'composer.json': t.composer(answers.withJWT),
        '.env': envContent,
        '.gitignore': t.gitignore,
        'README.md': t.readme(answers.withJWT)
    };

    // Añadir archivos .env
    Object.entries(envFiles).forEach(([file, content]) => {
        write(base, file, content);
    });

    if (answers.withJWT) {
        files['core/JWT.php'] = t.jwt;
        files['core/AuthMiddleware.php'] = t.authMiddleware;
        files['app/Controllers/AuthController.php'] = t.authController;
        files['app/Models/UserModel.php'] = t.userModel;
        files['database/migrations/users.sql'] = t.usersMigration(answers.database);
        files['database/migrations/jwt_denylist.sql'] = t.jwtDenylistMigration(answers.database);
        files['database/migrations/refresh_tokens.sql'] = t.refreshTokenMigration(answers.database);
        files['app/Models/JwtDenylistModel.php'] = t.jwtDenylistModel;
        files['app/Models/RefreshTokenModel.php'] = t.refreshTokenModel;
    }

    Object.entries(files).forEach(([file, content]) => write(base, file, content));

    success(`Proyecto "${name}" creado con ${answers.database === 'mysql' ? 'MySQL' : 'SQL Server'}${answers.withJWT ? ' + JWT' : ''}.`);
    console.log(`\n➡️  cd ${name}`);
    console.log(`   composer install`);
    if (answers.withJWT) {
        console.log(`   # Ejecuta las migraciones de la base de datos en orden:`);
        console.log(`   # 1. database/migrations/users.sql`);
        console.log(`   # 2. database/migrations/jwt_denylist.sql`);
        console.log(`   # 3. database/migrations/refresh_tokens.sql`);
    }
    console.log(`   php-init server\n`);
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

async function makeModel(name, tableName) {
    if (!inProject()) error('No estás en un proyecto.');

    let finalTableName = tableName;

    if (!finalTableName) {
        const answers = await inquirer.prompt([
            {
                type: 'input',
                name: 'tableNamePrompt',
                message: 'Nombre de la tabla en la BD:',
                default: name.toLowerCase() + 's'
            }
        ]);
        finalTableName = answers.tableNamePrompt;
    }

    const className = cap(name) + 'Model';
    const file = path.join(process.cwd(), 'app/Models', `${className}.php`);

    if (exists(file)) return warn(`${className}.php ya existe.`);

    write(process.cwd(), `app/Models/${className}.php`, t.crudModel(className, finalTableName));
    success(`Creado: app/Models/${className}.php`);
}

async function makeMiddleware(name) {
    if (!inProject()) error('No estás en un proyecto.');

    const className = cap(name) + 'Middleware';
    const file = path.join(process.cwd(), 'core', `${className}.php`);

    if (exists(file)) return warn(`${className}.php ya existe.`);

    write(process.cwd(), `core/${className}.php`, t.customMiddleware(className));
    success(`Creado: core/${className}.php`);

    console.log(`\n📝 Próximos pasos:`);
    console.log(`   1. Implementa la lógica en: core/${className}.php`);
    console.log(`   2. Registra el middleware en public/index.php:`);
    console.log(`      Middleware::register('${name.toLowerCase()}', 'Core\\\\${className}::handle');`);
    console.log(`   3. Usa el middleware en tus rutas:`);
    console.log(`      $router->get('/ruta', 'Controller', 'method')->middleware('${name.toLowerCase()}');\n`);
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

async function makeTest(name) {
    if (!inProject()) error('No estás en un proyecto.');

    const className = cap(name) + 'Test';
    const file = path.join(process.cwd(), 'tests', `${className}.php`);

    if (exists(file)) return warn(`${className}.php ya existe.`);

    write(process.cwd(), `tests/${className}.php`, t.testTemplate(name));
    success(`Creado: tests/${className}.php`);
}

function listRoutes() {
    if (!inProject()) error('No estás en un proyecto.');

    const file = path.join(process.cwd(), 'app/Routes/web.php');
    if (!exists(file)) error('No se encontró web.php');

    const content = fs.readFileSync(file, 'utf8');
    const regex = /\$router->(get|post|put|delete)\s*\(\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*\)(?:->middleware\((.*?)\))?/g;

    console.log('\n📋 Rutas registradas:');
    console.log('-'.repeat(90));
    console.log('Método  | URI                  | Controlador          | Acción           | Middlewares');
    console.log('-'.repeat(90));

    let match;
    while ((match = regex.exec(content)) !== null) {
        const [, method, uri, controller, action, middlewares] = match;
        const mw = middlewares ? middlewares.replace(/['"]/g, '').split(',').map(m => m.trim()).join(', ') : '-';
        console.log(`${method.toUpperCase().padEnd(7)} | ${uri.padEnd(20)} | ${controller.padEnd(20)} | ${action.padEnd(16)} | ${mw}`);
    }
    console.log('-'.repeat(90) + '\n');
}

async function startServer() {
    if (!inProject()) error('No estás en un proyecto.');

    const publicDir = path.join(process.cwd(), 'public');
    if (!exists(publicDir)) error('Directorio public/ no encontrado.');

    const answers = await inquirer.prompt([
        {
            type: 'input',
            name: 'host',
            message: 'Host:',
            default: 'localhost',
            validate: (input) => {
                if (!input) return 'El host no puede estar vacío.';
                if (/[^a-zA-Z0-9.-]/.test(input)) {
                    return 'Host inválido. Solo se permiten caracteres alfanuméricos, puntos y guiones.';
                }
                return true;
            }
        },
        {
            type: 'input',
            name: 'port',
            message: 'Puerto:',
            default: '8000',
            validate: (input) => {
                const port = parseInt(input);
                if (isNaN(port) || port < 1 || port > 65535) {
                    return 'Puerto inválido (1-65535)';
                }
                return true;
            }
        }
    ]);

    const { host, port } = answers;

    console.log('\n🚀 Iniciando servidor de desarrollo...');
    console.log(`📡 Servidor corriendo en: http://${host}:${port}`);
    console.log('⏹️  Presiona Ctrl+C para detener\n');

    const server = spawn('php', [
        '-S',
        `${host}:${port}`,
        '-t',
        'public'
    ], {
        stdio: 'inherit',
        shell: true
    });

    server.on('error', (err) => {
        error(`Error al iniciar servidor: ${err.message}`);
    });

    server.on('close', (code) => {
        if (code !== 0 && code !== null) {
            console.log(`\n⚠️  Servidor detenido con código: ${code}`);
        } else {
            console.log('\n👋 Servidor detenido');
        }
    });

    process.on('SIGINT', () => {
        console.log('\n\n⏹️  Deteniendo servidor...');
        server.kill('SIGINT');
        process.exit(0);
    });
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
    .command('make:model <nombre> [tabla]')
    .description('Crea un modelo')
    .action(makeModel);

program
    .command('make:middleware <nombre>')
    .description('Crea un middleware personalizado')
    .action(makeMiddleware);

program
    .command('make:crud <nombre>')
    .description('Crea controlador, modelo y rutas CRUD')
    .action(makeCrud);

program
    .command('make:test <nombre>')
    .description('Crea un test')
    .action(makeTest);

program
    .command('list:routes')
    .description('Lista todas las rutas')
    .action(listRoutes);

program
    .command('server')
    .description('Inicia el servidor de desarrollo')
    .action(startServer);

program.parse();