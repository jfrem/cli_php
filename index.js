#!/usr/bin/env node
import { Command } from "commander";
import inquirer from "inquirer";
import fs from "fs-extra";
import path from "path";
import crypto from "crypto";
import { spawn } from "child_process";
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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
    const baseResolved = path.resolve(base);
    const full = path.resolve(baseResolved, file);

    if (!full.startsWith(baseResolved + path.sep)) {
        error('Ruta de salida inválida (posible path traversal)');
    }

    fs.ensureDirSync(path.dirname(full));
    const tmp = full + '.tmp-' + crypto.randomBytes(6).toString('hex');
    const normalized = String(content).replace(/\r?\n/g, '\n').trim() + '\n';
    fs.writeFileSync(tmp, normalized, { encoding: 'utf8', mode: 0o644, flag: 'w' });
    fs.renameSync(tmp, full);
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
// Validación de seguridad para nombres
// ==============================

const sanitizeClassName = (input, entityType = 'class') => {
    if (typeof input !== 'string') {
        throw new Error(`Nombre de ${entityType} debe ser texto`);
    }

    if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(input)) {
        throw new Error(`Nombre inválido para ${entityType}: "${input}". Solo A-Z, a-z, 0-9, _, empezando con letra.`);
    }

    if (input.length > 50) {
        throw new Error(`Nombre demasiado largo: "${input}"`);
    }

    return input;
};

const sanitizeTableName = (input) => {
    if (typeof input !== 'string') {
        throw new Error('Nombre de tabla debe ser texto');
    }

    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(input)) {
        throw new Error(`Nombre de tabla inválido: "${input}". Solo a-z, A-Z, 0-9, _, empezando con letra o _.`);
    }

    return input;
};

// Validación adicional contra nombres peligrosos de objetos
const ensureSafeName = (input, entityType = 'nombre') => {
    if (typeof input !== 'string') {
        throw new Error(`Nombre de ${entityType} debe ser texto`);
    }
    const banned = ['__proto__', 'prototype', 'constructor'];
    if (banned.includes(input.toLowerCase())) {
        throw new Error(`Nombre reservado no permitido: "${input}"`);
    }
    return input;
};

// ==============================
// Templates completos y corregidos
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
use Core\\Logger;

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

// Manejo global de excepciones
set_exception_handler(function ($e) {
    Logger::error('Unhandled exception: ' . $e->getMessage(), ['exception' => $e]);
    
    if (getenv('APP_ENV') === 'production') {
        \\Core\\Response::error('Internal server error', 500);
    } else {
        \\Core\\Response::error($e->getMessage(), 500);
    }
});

try {
    Env::load();

    // Rate limiting
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    try {
        RateLimit::check($clientIp);
    } catch (\\Exception $e) {
        // En producción, fallar silenciosamente es mejor que exponer errores
        if (getenv('APP_ENV') === 'development') {
            throw $e;
        }
        // En producción, permitir la solicitud si el rate limiting falla
        Logger::error('Rate limiting failed: ' . $e->getMessage());
    }

    // Registrar middlewares
    Middleware::register('auth', 'Core\\AuthMiddleware::handle');

    $router = new Router();
    require __DIR__ . '/../app/Routes/web.php';
    
    $router->dispatch();
} catch (\\Exception $e) {
    Logger::error('Application bootstrap failed: ' . $e->getMessage());
    \\Core\\Response::error('Application error', 500);
}`,

    htaccess: `RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php [QSA,L]`,

    controller: `<?php
namespace App\\Controllers;

use Core\\Response;
use Core\\Validator;

class Controller
{
    protected $model;

    public function index()
    {
        Response::success([], 'Controlador base funcionando');
    }

    /**
     * Obtiene el cuerpo de la petición como JSON
     * Solo acepta application/json para APIs REST
     */
    protected function getBody(): array
    {
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
        
        // Solo aceptar JSON para APIs REST
        if (strpos($contentType, 'application/json') === false) {
            Response::error('Content-Type must be application/json', 415);
        }
        
        // Límite de tamaño de JSON (por defecto 1MB, configurable vía MAX_JSON_SIZE)
        $maxSize = (int)(getenv('MAX_JSON_SIZE') ?: 1048576);
        $contentLength = isset($_SERVER['CONTENT_LENGTH']) ? (int)$_SERVER['CONTENT_LENGTH'] : 0;
        if ($contentLength > 0 && $maxSize > 0 && $contentLength > $maxSize) {
            Response::error('Payload Too Large', 413);
        }
        
        $input = file_get_contents('php://input');
        if ($maxSize > 0 && strlen($input) > $maxSize) {
            Response::error('Payload Too Large', 413);
        }
        
        if (empty($input)) {
            return [];
        }
        
        $data = json_decode($input, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            Response::error('Invalid JSON payload: ' . json_last_error_msg(), 400);
        }
        
        return is_array($data) ? $data : [];
    }

    /**
     * Validación conveniente para datos de entrada
     */
    protected function validate(array $rules): array
    {
        $data = $this->getBody();
        $errors = Validator::validate($data, $rules);
        
        if (!empty($errors)) {
            Response::error('Errores de validación', 422, $errors);
        }
        
        return $data;
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
    
    /**
     * Lista blanca de columnas que pueden ser asignadas masivamente
     * DEBE ser definida en cada modelo hijo para seguridad
     */
    protected $fillable = [];

    public function __construct()
    {
        $this->db = Database::getConnection();
    }

    /**
     * Valida que el modelo tenga definida la propiedad $fillable
     * @throws \\RuntimeException
     */
    protected function validateFillable(): void
    {
        if (empty($this->fillable)) {
            throw new \\RuntimeException(
                'Security: $fillable must be defined in ' . static::class
            );
        }
    }

    /**
     * Filtra los datos usando la lista blanca $fillable
     */
    protected function filterFillable(array $data): array
    {
        $this->validateFillable();
        return array_intersect_key($data, array_flip($this->fillable));
    }

    protected function escapeIdentifier(string $identifier): string
    {
        $dbType = $_ENV['DB_TYPE'] ?? 'mysql';
        
        switch ($dbType) {
            case 'sqlsrv':
                return '[' . str_replace(']', ']]', $identifier) . ']';
            case 'mysql':
            default:
                $backtick = chr(96);
                return $backtick . str_replace($backtick, $backtick . $backtick, $identifier) . $backtick;
        }
    }

    protected function getQuotedTable(): string
    {
        if (empty($this->table)) {
            throw new \\Exception('La propiedad $table no puede estar vacía en el modelo.');
        }

        // Validate table name to prevent SQL injection
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $this->table)) {
            throw new \\RuntimeException('Nombre de tabla inválido: ' . $this->table);
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
        // Filtrar datos por la lista blanca $fillable
        $data = $this->filterFillable($data);
        
        if (empty($data)) {
            throw new \\InvalidArgumentException('No valid data provided for mass assignment');
        }

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
        // Filtrar datos por la lista blanca $fillable
        $data = $this->filterFillable($data);
        
        if (empty($data)) {
            throw new \\InvalidArgumentException('No valid data provided for mass assignment');
        }

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

    /**
     * Respuesta paginada estandarizada
     * @param array $data Datos de la página actual
     * @param int $page Página actual
     * @param int $perPage Elementos por página
     * @param int $total Total de elementos
     * @param string $message Mensaje opcional
     */
    public static function paginated(array $data, int $page, int $perPage, int $total, string $message = 'Operación exitosa')
    {
        $totalPages = (int)ceil($total / $perPage);
        
        self::json([
            'success' => true,
            'message' => $message,
            'data' => $data,
            'meta' => [
                'page' => $page,
                'per_page' => $perPage,
                'total' => $total,
                'total_pages' => $totalPages,
                'has_next_page' => $page < $totalPages,
                'has_prev_page' => $page > 1
            ]
        ]);
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
use PDOException;

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
            throw new \\RuntimeException('Error de conexión a la base de datos', 500, $e);
        }
    }
}`;
        }

        return `<?php
namespace Core;

use PDO;
use PDOException;

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
            throw new \\RuntimeException('Error de conexión a la base de datos', 500, $e);
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
                throw new \\RuntimeException('Error Crítico: JWT_SECRET no está definido en producción.');
            }
            if (strlen($secret) < 32) {
                throw new \\RuntimeException('Error Crítico: JWT_SECRET debe tener al menos 32 caracteres en producción.');
            }
            if ($secret === 'your_secret_key_change_in_production_min_32_chars') {
                throw new \\RuntimeException('Error Crítico: El JWT_SECRET por defecto está siendo usado en producción.');
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

use App\\Models\\JwtDenylistModel;
use App\\Models\\RefreshTokenModel;
use App\\Models\\UserModel;
use Core\\AuthMiddleware;
use Core\\Env;
use Core\\JWT;
use Core\\Logger;
use Core\\Response;
use Core\\Validator;

class AuthController extends Controller
{
    private UserModel $userModel;
    private RefreshTokenModel $refreshTokenModel;

    public function __construct()
    {
        $this->userModel = new UserModel();
        $this->refreshTokenModel = new RefreshTokenModel();
    }

    private function getRefreshCookieName(): string
    {
        return Env::get('REFRESH_TOKEN_COOKIE_NAME', 'formvin_refresh_token');
    }

    private function buildRefreshCookieOptions(bool $expire = false): array
    {
        $secureDefault = Env::get('APP_ENV', 'production') !== 'development';
        $secure = filter_var(
            Env::get('COOKIE_SECURE', $secureDefault ? 'true' : 'false'),
            FILTER_VALIDATE_BOOLEAN
        );

        $options = [
            'expires' => $expire ? time() - 3600 : 0,
            'path' => Env::get('COOKIE_PATH', '/'),
            'secure' => $secure,
            'httponly' => true,
            'samesite' => Env::get('COOKIE_SAMESITE', 'Strict'),
        ];

        $domain = Env::get('COOKIE_DOMAIN', '');
        if (!empty($domain)) {
            $options['domain'] = $domain;
        }

        return $options;
    }

    private function queueRefreshTokenCookie(?string $token, int $ttl): void
    {
        $options = $this->buildRefreshCookieOptions();
        $options['expires'] = time() + $ttl;

        setcookie($this->getRefreshCookieName(), $token ?? '', $options);
    }

    private function clearRefreshTokenCookie(): void
    {
        $options = $this->buildRefreshCookieOptions(true);
        setcookie($this->getRefreshCookieName(), '', $options);
    }

    private function getRefreshTokenFromCookie(): string
    {
        return $_COOKIE[$this->getRefreshCookieName()] ?? '';
    }

    public function register()
    {
        try {
            $body = $this->getBody();

            $errors = Validator::validate($body, [
                'email' => 'required|email',
                'password' => 'required|min:6',
                'name' => 'required|min:2',
            ]);

            if (!empty($errors)) {
                Response::error('Errores de validacion', 422, $errors);
            }

            $existing = $this->userModel->findByEmail($body['email']);
            if ($existing) {
                Logger::warning('Intento de registro con email duplicado');
                Response::error('El email ya esta registrado', 409);
            }

            $role = 'user';
            if (isset($body['role']) && $body['role'] === 'admin') {
                Logger::warning('Intento de registro con rol admin no permitido');
            }

            $body['password'] = password_hash($body['password'], PASSWORD_BCRYPT);
            $body['role'] = $role;

            $user = $this->userModel->create($body);
            unset($user['password']);

            $token = JWT::encode([
                'user_id' => $user['id'],
                'email' => $user['email'],
                'role' => $user['role'],
            ]);

            Logger::info('Usuario registrado exitosamente', ['user_id' => $user['id']]);

            Response::success(
                [
                    'user' => $user,
                    'token' => $token,
                ],
                'Usuario registrado correctamente',
                201
            );
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
            $errors = Validator::validate($body, [
                'email' => 'required|email',
                'password' => 'required',
            ]);
            if (!empty($errors)) {
                Response::error('Errores de validacion', 422, $errors);
            }

            $user = $this->userModel->findByEmail($body['email']);
            if (!$user || !password_verify($body['password'], $user['password'])) {
                Logger::warning('Intento de login fallido', ['email' => $body['email'] ?? null]);
                Response::error('Credenciales invalidas', 401);
            }

            unset($user['password']);

            $accessToken = JWT::encode([
                'user_id' => $user['id'],
                'email' => $user['email'],
                'role' => $user['role'],
            ]);

            $refreshTokenTtl = (int)Env::get('JWT_REFRESH_TOKEN_EXPIRATION', 2592000);
            $this->refreshTokenModel->deleteAllForUser($user['id']);
            $refreshToken = $this->refreshTokenModel->createForUser($user['id'], $refreshTokenTtl);
            $this->queueRefreshTokenCookie($refreshToken, $refreshTokenTtl);

            Logger::info('Login exitoso', ['user_id' => $user['id']]);

            Response::success(
                [
                    'user' => $user,
                    'access_token' => $accessToken,
                ],
                'Login exitoso'
            );
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
            $refreshToken = $this->getRefreshTokenFromCookie();
            if (empty($refreshToken)) {
                Response::error('Refresh token no disponible', 401);
            }

            $tokenData = $this->refreshTokenModel->findByToken($refreshToken);

            if (!$tokenData) {
                $this->clearRefreshTokenCookie();
                Response::error('Refresh token inválido', 401);
            }

            if (strtotime($tokenData['expires_at']) < time()) {
                $this->refreshTokenModel->delete($tokenData['id']);
                $this->clearRefreshTokenCookie();
                Response::error('Refresh token expirado', 401);
            }

            $this->refreshTokenModel->delete($tokenData['id']);

            $user = $this->userModel->find($tokenData['user_id']);
            if (!$user) {
                $this->clearRefreshTokenCookie();
                Response::error('Usuario no encontrado', 404);
            }

            $newAccessToken = JWT::encode([
                'user_id' => $user['id'],
                'email' => $user['email'],
                'role' => $user['role'],
            ]);

            $refreshTokenTtl = (int)Env::get('JWT_REFRESH_TOKEN_EXPIRATION', 2592000);
            $newRefreshToken = $this->refreshTokenModel->createForUser($user['id'], $refreshTokenTtl);
            $this->queueRefreshTokenCookie($newRefreshToken, $refreshTokenTtl);

            Response::success(
                [
                    'access_token' => $newAccessToken,
                ],
                'Tokens actualizados'
            );
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
            if ($payload && isset($payload->jti, $payload->exp, $payload->user_id)) {
                (new JwtDenylistModel())->deny($payload->jti, $payload->exp);
                $this->refreshTokenModel->deleteAllForUser($payload->user_id);
            }

            $refreshToken = $this->getRefreshTokenFromCookie();
            if ($refreshToken) {
                $tokenData = $this->refreshTokenModel->findByToken($refreshToken);
                if ($tokenData) {
                    $this->refreshTokenModel->delete($tokenData['id']);
                }
            }

            $this->clearRefreshTokenCookie();

            Response::success(null, 'Sesion cerrada correctamente');
        } catch (\\PDOException $e) {
            $errorId = uniqid('err_');
            Logger::error("Error de BD en logout [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error de base de datos. ID de error: {$errorId}", 500);
        } catch (\\Exception $e) {
            $errorId = uniqid('err_');
            Logger::error("Error al cerrar sesion [ID: {$errorId}]", ['exception' => $e]);
            Response::error("Error al cerrar sesion. ID: {$errorId}", 500);
        }
    }

    public function me()
    {
        try {
            $payload = AuthMiddleware::getAuthUser();
            if (!$payload || !isset($payload->user_id)) {
                Response::error('Token no valido', 401);
            }

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
    protected $fillable = ['email', 'password', 'name', 'role'];

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
            @mkdir(self::$logDir, 0750, true);
        }

        $logFile = self::$logDir . '/app-' . date('Y-m-d') . '.log';

        // Sanitize log file path to prevent directory traversal
        $realLogDir = realpath(self::$logDir);
        $realLogFile = realpath(dirname($logFile));

        if (!$realLogDir || !$realLogFile || strpos($realLogFile, $realLogDir) !== 0) {
            // Log to a safe fallback or throw an exception
            error_log("Security: Invalid log file path detected: {$logFile}");
            return;
        }

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
        file_put_contents($logFile, $jsonEntry . "\\n", FILE_APPEND | LOCK_EX);
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
        
        try {
            if (!is_dir($logDir)) {
                if (!mkdir($logDir, 0755, true) && !is_dir($logDir)) {
                    throw new \\RuntimeException('No se pudo crear directorio de logs');
                }
            }
            
            $lock = fopen(self::$lockFile, 'c');
            if (!$lock) {
                throw new \\RuntimeException('No se pudo crear archivo de lock');
            }
            
            // Timeout más estricto para evitar bloqueos prolongados
            $startTime = microtime(true);
            $timeout = 2;
            
            while (!flock($lock, LOCK_EX | LOCK_NB)) {
                if (microtime(true) - $startTime > $timeout) {
                    fclose($lock);
                    throw new \\RuntimeException('Timeout al obtener lock para rate limiting');
                }
                usleep(100000); // 100ms
            }
            
            try {
                return $callback();
            } finally {
                flock($lock, LOCK_UN);
                fclose($lock);
            }
        } catch (\\Exception $e) {
            Logger::error('Error en rate limiting: ' . $e->getMessage());
            
            // En producción, fallar silenciosamente es más seguro
            if (Env::get('APP_ENV') === 'production') {
                // Permitir la solicitud si el rate limiting falla
                return true;
            }
            
            throw $e; // En desarrollo, mostrar el error
        }
    }
    
    private static function getStorage(): array
    {
        if (!file_exists(self::$storageFile)) {
            return [];
        }
        
        $content = file_get_contents(self::$storageFile);
        $data = json_decode($content, true);
        return is_array($data) ? $data : [];
    }
    
    private static function saveStorage(array $data): void
    {
        $logDir = dirname(self::$storageFile);
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
        $tmp = self::$storageFile . '.tmp.' . uniqid();
        file_put_contents($tmp, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
        rename($tmp, self::$storageFile);
    }
    
    private static function cleanupOldEntries(int $window): void
    {
        $storage = self::getStorage();
        $now = time();
        $changed = false;
        
        foreach ($storage as $key => $data) {
            if (!isset($data['requests']) || !is_array($data['requests'])) {
                unset($storage[$key]);
                $changed = true;
                continue;
            }
            
            // Filtrar requests antiguos
            $originalCount = count($data['requests']);
            $data['requests'] = array_filter(
                $data['requests'],
                fn($time) => $now - $time < $window
            );
            
            // Eliminar entrada si no hay requests recientes y no está bloqueada
            $allExpired = empty($data['requests']);
            $blockExpired = ($data['blocked_until'] ?? 0) < $now;
            
            if ($allExpired && $blockExpired) {
                unset($storage[$key]);
                $changed = true;
            } elseif (count($data['requests']) !== $originalCount) {
                $storage[$key] = $data;
                $changed = true;
            }
        }
        
        if ($changed) {
            self::saveStorage($storage);
        }
    }
    
    public static function check(string $ip, int $limit = 100, int $window = 60): bool
    {
        try {
            return self::withLock(function() use ($ip, $limit, $window) {
                $storage = self::getStorage();
                $now = time();
                $key = "ip_{$ip}";
                
                if (!isset($storage[$key])) {
                    $storage[$key] = ['requests' => [], 'blocked_until' => 0];
                }
                
                $entry = &$storage[$key];
                
                // Inicializar arrays si no existen
                if (!isset($entry['requests']) || !is_array($entry['requests'])) {
                    $entry['requests'] = [];
                }
                if (!isset($entry['blocked_until'])) {
                    $entry['blocked_until'] = 0;
                }
                
                if ($entry['blocked_until'] > $now) {
                    Logger::warning("IP bloqueada por rate limit: {$ip}");
                    Response::error('Demasiadas peticiones. Intenta de nuevo más tarde.', 429);
                }
                
                // Filtrar requests antiguos
                $entry['requests'] = array_filter(
                    $entry['requests'],
                    fn($time) => $now - $time < $window
                );
                
                if (count($entry['requests']) >= $limit) {
                    $entry['blocked_until'] = $now + $window;
                    self::saveStorage($storage);
                    Logger::warning("Rate limit excedido para IP: {$ip}");
                    Response::error('Demasiadas peticiones. Intenta de nuevo más tarde.', 429);
                }
                
                $entry['requests'][] = $now;
                self::saveStorage($storage);
                
                // Limpieza probabilística (1% de chance)
                if (rand(1, 100) === 1) {
                    self::cleanupOldEntries($window);
                }
                
                return true;
            });
        } catch (\\Exception $e) {
            // En producción, fallar silenciosamente es mejor que exponer errores
            if (Env::get('APP_ENV') === 'development') {
                throw $e;
            }
            
            // En producción, permitir la solicitud si el rate limiting falla
            Logger::error('Rate limiting failed: ' . $e->getMessage());
            return true;
        }
    }
    
    /**
     * Interfaz para futuras implementaciones con Redis/Memcached
     */
    public static function setStorageAdapter($adapter): void
    {
        // Para futura implementación con almacenamiento en memoria
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

# Cookie Configuration for Refresh Tokens
# REFRESH_TOKEN_COOKIE_NAME=formvin_refresh_token
# COOKIE_SECURE=true
# COOKIE_PATH=/
# COOKIE_SAMESITE=Lax # Strict, Lax, None
# COOKIE_DOMAIN= # .yourdomain.com (leave empty for current domain)

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
    role VARCHAR(50) DEFAULT 'user',
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
    role VARCHAR(50) DEFAULT 'user',
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
    protected $fillable = ['user_id', 'token_hash', 'expires_at'];

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
    protected $fillable = ['jti', 'expires_at'];

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

    passwordResetMigration: (dbType) => {
        if (dbType === 'mysql') {
            return `-- Tabla para tokens de recuperación de contraseña
CREATE TABLE IF NOT EXISTS password_resets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_password_resets_email (email),
    INDEX idx_password_resets_token (token_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`;
        }

        return `-- Tabla para tokens de recuperación de contraseña
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='password_resets' AND xtype='U')
CREATE TABLE password_resets (
    id INT IDENTITY(1,1) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT GETDATE()
);

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_password_resets_email')
CREATE INDEX idx_password_resets_email ON password_resets(email);

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_password_resets_token')
CREATE INDEX idx_password_resets_token ON password_resets(token_hash);`;
    },

    passwordResetModel: `<?php
namespace App\\Models;

class PasswordResetModel extends Model
{
    protected $table = 'password_resets';
    protected $fillable = ['email', 'token_hash', 'expires_at'];

    public function createToken(string $email, int $validity = 3600): string
    {
        // Limpiar tokens antiguos de este email
        $this->deleteByEmail($email);
        
        $token = bin2hex(random_bytes(32));
        $expires_at = date('Y-m-d H:i:s', time() + $validity);

        $this->create([
            'email' => $email,
            'token_hash' => hash('sha256', $token),
            'expires_at' => $expires_at
        ]);

        return $token;
    }

    public function findByToken(string $token)
    {
        $hash = hash('sha256', $token);
        $stmt = $this->db->prepare("SELECT * FROM {$this->getQuotedTable()} WHERE token_hash = ? AND expires_at > NOW()");
        $stmt->execute([$hash]);
        return $stmt->fetch();
    }

    public function deleteByEmail(string $email): bool
    {
        $stmt = $this->db->prepare("DELETE FROM {$this->getQuotedTable()} WHERE email = ?");
        return $stmt->execute([$email]);
    }

    public function cleanupExpired(): int
    {
        $stmt = $this->db->prepare("DELETE FROM {$this->getQuotedTable()} WHERE expires_at < NOW()");
        $stmt->execute();
        return $stmt->rowCount();
    }
}`,

    dockerCompose: (dbType) => {
        const mysqlService = `  mysql:
    image: mysql:8.0
    container_name: \${APP_NAME:-app}_mysql
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: \${DB_PASS:-secret}
      MYSQL_DATABASE: \${DB_NAME:-mi_base}
      MYSQL_USER: \${DB_USER:-user}
      MYSQL_PASSWORD: \${DB_PASS:-secret}
    ports:
      - "\${DB_PORT:-3306}:3306"
    volumes:
      - mysql_data:/var/lib/mysql
    networks:
      - app_network`;

        const sqlserverService = `  sqlserver:
    image: mcr.microsoft.com/mssql/server:2022-latest
    container_name: \${APP_NAME:-app}_sqlserver
    restart: unless-stopped
    environment:
      ACCEPT_EULA: "Y"
      SA_PASSWORD: \${DB_PASS:-YourStrong@Passw0rd}
      MSSQL_PID: Developer
    ports:
      - "\${DB_PORT:-1433}:1433"
    volumes:
      - sqlserver_data:/var/opt/mssql
    networks:
      - app_network`;

        return `version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: \${APP_NAME:-app}_php
    restart: unless-stopped
    working_dir: /var/www/html
    volumes:
      - ./:/var/www/html
      - ./logs:/var/www/html/logs
    ports:
      - "\${APP_PORT:-8000}:8000"
    depends_on:
      - ${dbType === 'mysql' ? 'mysql' : 'sqlserver'}
      - redis
    networks:
      - app_network
    command: php -S 0.0.0.0:8000 -t public

${dbType === 'mysql' ? mysqlService : sqlserverService}

  redis:
    image: redis:7-alpine
    container_name: \${APP_NAME:-app}_redis
    restart: unless-stopped
    ports:
      - "\${REDIS_PORT:-6379}:6379"
    volumes:
      - redis_data:/data
    networks:
      - app_network

networks:
  app_network:
    driver: bridge

volumes:
  ${dbType === 'mysql' ? 'mysql_data:' : 'sqlserver_data:'}
  redis_data:
`;
    },

    dockerfile: `FROM php:8.2-cli

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \\
    git \\
    unzip \\
    libzip-dev \\
    && docker-php-ext-install pdo pdo_mysql zip

# Instalar Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Configurar directorio de trabajo
WORKDIR /var/www/html

# Copiar archivos de la aplicación
COPY . .

# Instalar dependencias de PHP
RUN composer install --no-dev --optimize-autoloader

# Exponer puerto
EXPOSE 8000

CMD ["php", "-S", "0.0.0.0:8000", "-t", "public"]
`,

    dockerignore: `node_modules
vendor
.git
.env
.env.*
!.env.example
logs/*.log
*.tmp
.DS_Store
Thumbs.db
`,

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

    crudModel: (name, table, fillable = []) => `<?php
namespace App\\Models;

class ${name} extends Model
{
    protected $table = '${table}';
    protected $fillable = [${fillable.length > 0 ? `'${fillable.join("', '")}'` : ''}];${fillable.length === 0 ? ' // ¡DEFINIR columnas permitidas para asignación masiva!' : ''}
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

## ⚠️ IMPORTANTE: Seguridad

### Protección contra Inyección SQL
Todos los modelos ahora requieren la propiedad **\$fillable** que define una lista blanca de columnas que pueden ser asignadas masivamente. Esto previene ataques de inyección SQL mediante manipulación de nombres de columnas.

**Ejemplo seguro:**
\`\`\`php
class UserModel extends Model
{
    protected $table = 'users';
    protected $fillable = ['email', 'password', 'name']; // Solo estas columnas
}
\`\`\`

### Validación de Entradas
- Todos los nombres de clases y tablas son validados contra path traversal
- El cuerpo de las peticiones solo acepta JSON
- Parámetros de ruta son sanitizados automáticamente

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

Este proyecto implementa un sistema de autenticación JWT robusto con las siguientes características de seguridad:
- **Tokens de Acceso (Access Tokens):** De corta duración, se envían en el header \`Authorization: Bearer {token}\`.
- **Tokens de Refresco (Refresh Tokens):** De larga duración, se gestionan de forma segura mediante **cookies HttpOnly y Secure**. Esto previene ataques XSS, ya que el JavaScript del frontend no puede acceder a ellos.
- **Rotación de Tokens de Refresco:** Cada vez que se usa un refresh token (ya sea al iniciar sesión o al refrescar un access token), el token antiguo se invalida y se emite uno nuevo. Esto minimiza la ventana de oportunidad si un refresh token es comprometido.
- **Revocación de Tokens:** Los tokens pueden ser invalidados explícitamente (ej. al cerrar sesión).
- **Roles de Usuario:** El rol del usuario se incluye en el payload del JWT para facilitar el control de acceso basado en roles (RBAC).

### Registro
\`\`\`bash
POST /auth/register
{
  "email": "user@example.com",
  "password": "password123",
  "name": "Usuario"
}
\`\`\`
*Nota: El rol del usuario se asigna automáticamente a 'user' por seguridad. Intentar registrarse con un rol 'admin' será ignorado y logueado.*

### Login
\`\`\`bash
POST /auth/login
{
  "email": "user@example.com",
  "password": "123"
}
\`\`\`
*Respuesta:*
- El \`access_token\` se devuelve en el cuerpo de la respuesta JSON.
- El \`refresh_token\` se establece automáticamente como una **cookie HttpOnly** en tu navegador.

### Refrescar Token
\`\`\`bash
POST /auth/refresh
\`\`\`
*Este endpoint no requiere un cuerpo de solicitud. El \`refresh_token\` se leerá automáticamente de la cookie HttpOnly.*
*Respuesta:*
- Un nuevo \`access_token\` se devuelve en el cuerpo de la respuesta JSON.
- Un nuevo \`refresh_token\` se establece automáticamente como una **nueva cookie HttpOnly**, invalidando el anterior.

### Cerrar Sesión
\`\`\`bash
POST /auth/logout
Headers:
  Authorization: Bearer {access_token}
\`\`\`
*Este endpoint invalida el \`access_token\` actual y el \`refresh_token\` asociado (borrando la cookie HttpOnly y el registro en la base de datos).*

### Obtener usuario autenticado
\`\`\`bash
GET /auth/me
Headers:
  Authorization: Bearer {access_token}
\`\`\`

### Configuración de Cookies para Refresh Tokens
Puedes configurar el comportamiento de las cookies del refresh token en tu archivo \`.env\`:
\`\`\`dotenv
REFRESH_TOKEN_COOKIE_NAME=formvin_refresh_token
COOKIE_SECURE=true
COOKIE_PATH=/
COOKIE_SAMESITE=Lax # Opciones: Strict, Lax, None
COOKIE_DOMAIN= # Ej: .tudominio.com (dejar vacío para el dominio actual)
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
    $user = AuthMiddleware::getAuthUser();
    // $user contiene: { user_id, email, jti, iat, exp }
}
\`\`\`
` : ''}

## Manejo de Métodos HTTP

### APIs REST con JSON
Para clientes API (JavaScript, mobile apps), usa los métodos reales con JSON:

\`\`\`javascript
// POST real
fetch('/products', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'New Product', price: 100 })
});

// PUT real
fetch('/products/1', {
    method: 'PUT', 
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Updated Product' })
});

// DELETE real  
fetch('/products/1', {
    method: 'DELETE'
});
\`\`\`

El sistema solo acepta \`application/json\` para el cuerpo de las peticiones.

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

# Generar código (con validación de seguridad)
php-init make:controller Producto
php-init make:model Producto
php-init make:middleware Admin
php-init make:crud Producto
php-init make:test Producto

# Utilidades
php-init list:routes
php-init server
php-init db:migrate
\`\`\`

## Características de Seguridad

- ✅ **Protección contra inyección SQL** con lista blanca \$fillable
- ✅ **Validación de path traversal** en comandos CLI
- ✅ **Manejo de errores robusto** sin exit/die abruptos
- ✅ **Validación estricta de JSON** en todas las peticiones
- ✅ **Rate limiting mejorado** con timeouts y locking
- ✅ **Logging estructurado** con sanitización de datos sensibles
- ✅ **Sanitización** automática de parámetros de ruta
- ✅ **Protección contra SQL Injection** con escapado de identificadores y prepared statements
${withJWT ? '- ✅ **Autenticación JWT** con refresh tokens y revocación' : ''}
- ✅ **CORS** configurado para desarrollo y producción
- ✅ **PSR-4 autoloading** con Composer
- ✅ **Health checks** automáticos
- ✅ **Múltiples entornos** de configuración
- ✅ **Compatibilidad multi-BD** (MySQL y SQL Server)

## Rate Limiting

El sistema incluye rate limiting por IP (100 peticiones por minuto por defecto). Para producción con alto tráfico, se recomienda:

1. **Redis/Memcached**: Implementar almacenamiento en memoria
2. **Múltiples servidores**: Usar almacenamiento centralizado
3. **Configuración granular**: Ajustar límites por endpoint

## Estructura del proyecto

\`\`\`
├── app/
│   ├── Controllers/     # Controladores de la aplicación
│   ├── Models/          # Modelos de datos (con \$fillable)
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
- File locking con timeout para prevenir race conditions
- Limpieza automática de IPs antiguas (1% de probabilidad por request)
- Almacenamiento en JSON con validación

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

async function newProject(name, options) {
    let answers;

    if (options.database && options.dbHost && options.dbName && options.dbUser) {
        answers = {
            database: options.database,
            withJWT: options.jwt,
            dbHost: options.dbHost,
            dbPort: options.dbPort || (options.database === 'mysql' ? '3306' : '1433'),
            dbName: options.dbName,
            dbUser: options.dbUser,
            dbPass: options.dbPass || ''
        };
    } else {
        answers = await inquirer.prompt([
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
    }

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
        console.log(`   # Ejecuta las migraciones de la base de datos:`);
        console.log(`   php-init db:migrate`);
    }
    console.log(`   php-init server\n`);
}

async function makeController(name) {
    if (!inProject()) error('No estás en un proyecto.');

    try {
        name = ensureSafeName(sanitizeClassName(name, 'controlador'), 'controlador');
        const className = cap(name) + 'Controller';
        const file = path.join(process.cwd(), 'app/Controllers', `${className}.php`);

        if (exists(file)) return warn(`${className}.php ya existe.`);

        const model = cap(name) + 'Model';
        write(process.cwd(), `app/Controllers/${className}.php`, t.crudController(className, model));
        success(`Creado: app/Controllers/${className}.php`);
    } catch (err) {
        error(`Error de seguridad: ${err.message}`);
    }
}

async function makeModel(name, tableName) {
    if (!inProject()) error('No estás en un proyecto.');

    try {
        name = ensureSafeName(sanitizeClassName(name, 'modelo'), 'modelo');

        let finalTableName = tableName;
        if (!finalTableName) {
            const answers = await inquirer.prompt([
                {
                    type: 'input',
                    name: 'tableNamePrompt',
                    message: 'Nombre de la tabla en la BD:',
                    default: name.toLowerCase() + 's',
                    validate: (input) => {
                        try {
                            ensureSafeName(sanitizeTableName(input), 'tabla');
                            return true;
                        } catch (err) {
                            return err.message;
                        }
                    }
                }
            ]);
            finalTableName = answers.tableNamePrompt;
        } else {
            finalTableName = ensureSafeName(sanitizeTableName(finalTableName), 'tabla');
        }

        // Preguntar por columnas fillable
        const fillableAnswers = await inquirer.prompt([
            {
                type: 'confirm',
                name: 'defineFillable',
                message: '¿Quieres definir las columnas fillable ahora?',
                default: false
            }
        ]);

        let fillableColumns = [];
        if (fillableAnswers.defineFillable) {
            const columnsAnswer = await inquirer.prompt([
                {
                    type: 'input',
                    name: 'columns',
                    message: 'Introduce los nombres de las columnas fillable (separados por comas):',
                    validate: (input) => {
                        if (!input.trim()) return 'Debes introducir al menos una columna';
                        const cols = input.split(',').map(c => c.trim()).filter(c => c);
                        if (cols.length === 0) return 'Debes introducir al menos una columna';
                        // Validar que cada columna sea un nombre válido
                        for (const col of cols) {
                            if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(col)) {
                                return `Nombre de columna inválido: "${col}". Solo a-z, A-Z, 0-9, _, empezando con letra o _.`;
                            }
                        }
                        return true;
                    }
                }
            ]);
            fillableColumns = columnsAnswer.columns.split(',').map(c => c.trim()).filter(c => c);
        }

        const className = cap(name) + 'Model';
        const file = path.join(process.cwd(), 'app/Models', `${className}.php`);

        if (exists(file)) return warn(`${className}.php ya existe.`);

        write(process.cwd(), `app/Models/${className}.php`, t.crudModel(className, finalTableName, fillableColumns));
        success(`Creado: app/Models/${className}.php`);

        if (fillableColumns.length === 0) {
            console.log('\n📝 Recuerda definir la propiedad $fillable en el modelo:');
            console.log(`   protected $fillable = ['columna1', 'columna2'];`);
        }
    } catch (err) {
        error(`Error de seguridad: ${err.message}`);
    }
}

async function makeMiddleware(name) {
    if (!inProject()) error('No estás en un proyecto.');

    try {
        name = ensureSafeName(sanitizeClassName(name, 'middleware'), 'middleware');
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
    } catch (err) {
        error(`Error de seguridad: ${err.message}`);
    }
}

async function makeCrud(name) {
    if (!inProject()) error('No estás en un proyecto.');

    try {
        name = ensureSafeName(sanitizeClassName(name, 'CRUD'), 'CRUD');

        const answers = await inquirer.prompt([
            {
                type: 'input',
                name: 'tableName',
                message: 'Nombre de la tabla en la BD:',
                default: name.toLowerCase() + 's',
                validate: (input) => {
                    try {
                        ensureSafeName(sanitizeTableName(input), 'tabla');
                        return true;
                    } catch (err) {
                        return err.message;
                    }
                }
            }
        ]);

        const className = cap(name) + 'Model';
        const modelFile = path.join(process.cwd(), 'app/Models', `${className}.php`);

        let fillableColumns = [];
        if (!exists(modelFile)) {
            // Preguntar por columnas fillable
            const fillableAnswers = await inquirer.prompt([
                {
                    type: 'confirm',
                    name: 'defineFillable',
                    message: '¿Quieres definir las columnas fillable ahora?',
                    default: false
                }
            ]);

            if (fillableAnswers.defineFillable) {
                const columnsAnswer = await inquirer.prompt([
                    {
                        type: 'input',
                        name: 'columns',
                        message: 'Introduce los nombres de las columnas fillable (separados por comas):',
                        validate: (input) => {
                            if (!input.trim()) return 'Debes introducir al menos una columna';
                            const cols = input.split(',').map(c => c.trim()).filter(c => c);
                            if (cols.length === 0) return 'Debes introducir al menos una columna';
                            // Validar que cada columna sea un nombre válido
                            for (const col of cols) {
                                if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(col)) {
                                    return `Nombre de columna inválido: "${col}". Solo a-z, A-Z, 0-9, _, empezando con letra o _.`;
                                }
                            }
                            return true;
                        }
                    }
                ]);
                fillableColumns = columnsAnswer.columns.split(',').map(c => c.trim()).filter(c => c);
            }

            write(process.cwd(), `app/Models/${className}.php`, t.crudModel(className, answers.tableName, fillableColumns));
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
$router->put('${route}/{id}', '${controller}', 'update');
$router->delete('${route}/{id}', '${controller}', 'destroy');
`;

        fs.appendFileSync(routesFile, routes);
        success('CRUD completo creado.');

        if (fillableColumns.length === 0) {
            console.log('\n📝 Recuerda definir $fillable en el modelo:');
            console.log(`   protected $fillable = ['columna1', 'columna2'];`);
        }
    } catch (err) {
        error(`Error de seguridad: ${err.message}`);
    }
}

async function makeTest(name) {
    if (!inProject()) error('No estás en un proyecto.');

    try {
        name = ensureSafeName(sanitizeClassName(name, 'test'), 'test');
        const className = cap(name) + 'Test';
        const file = path.join(process.cwd(), 'tests', `${className}.php`);

        if (exists(file)) return warn(`${className}.php ya existe.`);

        write(process.cwd(), `tests/${className}.php`, t.testTemplate(name));
        success(`Creado: tests/${className}.php`);
    } catch (err) {
        error(`Error de seguridad: ${err.message}`);
    }
}

function listRoutes() {
    if (!inProject()) error('No estás en un proyecto.');

    const file = path.join(process.cwd(), 'app/Routes/web.php');
    if (!exists(file)) error('No se encontró web.php');

    const content = fs.readFileSync(file, 'utf8');
    const regex = /\$router->(get|post|put|delete)\s*\(\s*(['"])([^'"]+)\2\s*,\s*(['"])([^'"]+)\4\s*,\s*(['"])([^'"]+)\6\s*\)(?:->middleware\s*\(\s*(.*?)\s*\))?/g;

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
                if (!/^[a-zA-Z0-9.-]+$/.test(input)) {
                    return 'Host inválido. Solo se permiten caracteres alfanuméricos, puntos y guiones.';
                }
                if (input.length > 253) return 'Host demasiado largo.';
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
        shell: false,
        windowsHide: true
    });

    server.on('error', (err) => {
        if (err.code === 'EACCES') {
            error(`Puerto ${port} requiere privilegios de administrador`);
        } else if (err.code === 'EADDRINUSE') {
            error(`Puerto ${port} ya está en uso`);
        } else {
            error(`Error del servidor: ${err.message}`);
        }
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

async function runMigrations() {
    if (!inProject()) error('No estás en un proyecto.');
    const envPath = path.join(process.cwd(), '.env');
    if (!exists(envPath)) {
        error('No se encontró el archivo .env. Ejecuta primero: php-init new nombre-proyecto');
    }
    const envContent = fs.readFileSync(envPath, 'utf8');
    const envVars = {};
    envContent.split('\n').forEach(line => {
        const [key, value] = line.split('=');
        if (key && value) {
            envVars[key.trim()] = value.trim();
        }
    });

    const dbType = envVars.DB_TYPE || 'mysql';
    const dbHost = envVars.DB_HOST || 'localhost';
    const dbPort = envVars.DB_PORT || (dbType === 'mysql' ? '3306' : '1433');
    const dbName = envVars.DB_NAME || 'mi_base';
    const dbUser = envVars.DB_USER || (dbType === 'mysql' ? 'root' : 'sa');
    const dbPass = envVars.DB_PASS || '';

    const sanitizeIdent = (input, { allowDot = false } = {}) => {
        if (typeof input !== 'string') return '';
        const safe = input.replace(/[^a-zA-Z0-9_]/g, '');
        return safe.slice(0, 64);
    };

    const sanitizedDbHost = sanitizeIdent(dbHost);
    const sanitizedDbName = sanitizeIdent(dbName);
    const sanitizedDbUser = sanitizeIdent(dbUser);

    // Validaciones adicionales para credenciales de BD
    if (typeof dbPass !== 'string') {
        error('DB_PASS inválido');
    }
    if (dbPass.length > 128 || /[\r\n\0]/.test(dbPass)) {
        error('DB_PASS contiene caracteres no permitidos o es demasiado largo');
    }
    const portNum = parseInt(dbPort);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
        error('DB_PORT inválido (1-65535)');
    }

    if (dbHost !== sanitizedDbHost || dbName !== sanitizedDbName || dbUser !== sanitizedDbUser) {
        error('Caracteres inválidos detectados en los parámetros de conexión a la base de datos.');
    }

    if (!sanitizedDbName) {
        error('DB_NAME no está configurado en el archivo .env');
    }

    const migrationsDir = path.join(process.cwd(), 'database/migrations');
    if (!exists(migrationsDir)) {
        error('No se encontró el directorio de migraciones. ¿Has creado el proyecto con autenticación JWT?');
    }
    
    // Verificar archivos de migración
    const allMigrations = fs.readdirSync(migrationsDir).filter(f => f.endsWith('.sql'));
    
    if (allMigrations.length === 0) {
        error('No se encontraron archivos de migración (.sql) en database/migrations/');
    }

    // Ordenar migraciones según dependencias
    // users debe ir primero, luego las que dependen de users
    const migrationOrder = [
        'users.sql',
        'jwt_denylist.sql',
        'refresh_tokens.sql',
        'password_resets.sql'
    ];

    // Separar migraciones conocidas y desconocidas
    const knownMigrations = migrationOrder.filter(m => allMigrations.includes(m));
    const unknownMigrations = allMigrations
        .filter(m => !migrationOrder.includes(m))
        .sort(); // Ordenar alfabéticamente las desconocidas

    // Combinar: conocidas en orden + desconocidas alfabéticamente
    const migrationFiles = [...knownMigrations, ...unknownMigrations];

    console.log('📦 Ejecutando migraciones de base de datos...');
    console.log(`🔗 Conectando a: ${dbType}://${dbUser}@${dbHost}:${dbPort}/${dbName}`);
    console.log(`📋 Migraciones a ejecutar (${migrationFiles.length}):`);
    migrationFiles.forEach((file, index) => {
        console.log(`   ${index + 1}. ${file}`);
    });
    console.log('');
    
    try {
        // Crear conexión a la base de datos
        let connection;
        if (dbType === 'mysql') {
            const mysql = await import('mysql2/promise');
            // 1. Connect to MySQL server without specifying a database
            const tempConnection = await mysql.createConnection({
                host: sanitizedDbHost,
                port: parseInt(dbPort),
                user: sanitizedDbUser,
                password: dbPass
            });

            // 2. Create the database if it doesn't exist
            await tempConnection.execute(`CREATE DATABASE IF NOT EXISTS \`${sanitizedDbName}\``);
            await tempConnection.end();

            // 3. Now, connect to the specific database
            connection = await mysql.createConnection({
                host: sanitizedDbHost,
                port: parseInt(dbPort),
                user: sanitizedDbUser,
                password: dbPass,
                database: sanitizedDbName,
                multipleStatements: false
            });

        } else {
            // SQL Server
            const tedious = await import('tedious');
            const { Connection } = tedious;
            connection = await new Promise((resolve, reject) => {
                const config = {
                    server: sanitizedDbHost,
                    authentication: {
                        type: 'default',
                        options: {
                            userName: sanitizedDbUser,
                            password: dbPass
                        }
                    },
                    options: {
                        port: parseInt(dbPort),
                        encrypt: false,
                        trustServerCertificate: true
                    }
                };
                const conn = new Connection(config);
                conn.on('connect', (err) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(conn);
                    }
                });
                conn.connect();
            });

        }
        // Verificar/Crear base de datos
        try {
            if (dbType === 'mysql') {
                await connection.execute(`CREATE DATABASE IF NOT EXISTS \`${sanitizedDbName}\``);
                await connection.execute(`USE \`${sanitizedDbName}\``);
            } else {
                // Para SQL Server, asumimos que la base de datos ya existe
                // o el usuario tiene permisos para crearla
                console.log('ℹ️  Para SQL Server, asegúrate de que la base de datos exista');
            }
        } catch (e) {
            console.log('ℹ️  Usando base de datos existente...', e.message);
        }
        // Ejecutar migraciones en orden
        for (const migrationFile of migrationFiles) {
            const migrationPath = path.join(migrationsDir, migrationFile);
            const sql = fs.readFileSync(migrationPath, 'utf8');
            console.log(`\n🔄 Ejecutando: ${migrationFile}`);
            try {
                if (dbType === 'mysql') {
                    const statements = sql.split(';').filter(stmt => stmt.trim());
                    for (const statement of statements) {
                        if (statement.trim()) {
                            if (statement.trim().toUpperCase().startsWith('CREATE TABLE') ||
                                statement.trim().toUpperCase().startsWith('CREATE INDEX') ||
                                statement.trim().toUpperCase().startsWith('ALTER TABLE') ||
                                statement.trim().toUpperCase().startsWith('DROP TABLE') ||
                                statement.trim().toUpperCase().startsWith('DROP INDEX')) {
                                await connection.query(statement);
                            } else {
                                await connection.execute(statement);
                            }
                        }
                    }
                } else {
                    const statements = sql.split(';').filter(stmt => stmt.trim());
                    for (const statement of statements) {
                        if (statement.trim()) {
                            await new Promise((resolve, reject) => {
                                const request = new tedious.Request(statement.trim(), (err) => {
                                    if (err) reject(err);
                                    else resolve();
                                });
                                connection.execSql(request);
                            });
                        }
                    }
                }
                success(`✅ ${migrationFile} completado`);
            } catch (migrationError) {
                if (migrationError.code === 'ER_TABLE_EXISTS_ERROR' ||
                    migrationError.code === 'ER_DUP_KEYNAME' ||
                    migrationError.message?.includes('already exists')) {
                    warn(`⚠️  ${migrationFile} ya estaba aplicado`);
                } else {
                    throw migrationError;
                }
            }
        }
        if (dbType === 'mysql') {
            await connection.end();
        } else {
            connection.close();
        }
        success('\n🎉 ¡Todas las migraciones se ejecutaron correctamente!');
    } catch (error) {
        console.error('\n❌ Error ejecutando migraciones:');
        console.error(`   Mensaje: ${error.message}`);
        console.error(`   Código: ${error.code}`);
        console.error('\n💡 Solución:');
        console.error('   1. Verifica que tu servidor de base de datos esté corriendo');
        console.error('   2. Confirma las credenciales en el archivo .env');
        console.error('   3. Asegúrate de que la base de datos exista');
        if (dbType === 'mysql') {
            console.error('   4. Para MySQL: GRANT ALL PRIVILEGES ON *.* TO usuario@localhost');
        }
        process.exit(1);
    }
}

async function dbFresh(options = {}) {
    if (!inProject()) error('No estás en un proyecto.');
    
    // Si se pasa --force, saltar confirmación
    if (!options.force) {
        const answers = await inquirer.prompt([
            {
                type: 'confirm',
                name: 'confirm',
                message: '⚠️  Esto eliminará TODAS las tablas y datos. ¿Continuar?',
                default: false
            }
        ]);

        if (!answers.confirm) {
            console.log('❌ Operación cancelada');
            return;
        }
    } else {
        console.log('⚠️  Modo --force: Saltando confirmación');
    }

    console.log('🗑️  Eliminando base de datos...');
    
    const envPath = path.join(process.cwd(), '.env');
    const envContent = fs.readFileSync(envPath, 'utf8');
    const envVars = {};
    envContent.split('\n').forEach(line => {
        const [key, value] = line.split('=');
        if (key && value) {
            envVars[key.trim()] = value.trim();
        }
    });

    const dbType = envVars.DB_TYPE || 'mysql';
    const dbHost = envVars.DB_HOST || 'localhost';
    const dbPort = envVars.DB_PORT || (dbType === 'mysql' ? '3306' : '1433');
    const dbName = envVars.DB_NAME || 'mi_base';
    const dbUser = envVars.DB_USER || (dbType === 'mysql' ? 'root' : 'sa');
    const dbPass = envVars.DB_PASS || '';

    try {
        if (dbType === 'mysql') {
            const mysql = await import('mysql2/promise');
            const connection = await mysql.createConnection({
                host: dbHost,
                port: parseInt(dbPort),
                user: dbUser,
                password: dbPass
            });

            await connection.execute(`DROP DATABASE IF EXISTS \`${dbName}\``);
            await connection.end();
            success('✅ Base de datos eliminada');
        } else {
            console.log('⚠️  Para SQL Server, elimina la base de datos manualmente');
        }

        console.log('\n📦 Ejecutando migraciones...');
        await runMigrations();
    } catch (error) {
        console.error('❌ Error:', error.message);
        process.exit(1);
    }
}

async function makeAuthReset() {
    if (!inProject()) error('No estás en un proyecto.');

    const migrationsDir = path.join(process.cwd(), 'database/migrations');
    if (!exists(migrationsDir)) {
        error('Este proyecto no tiene autenticación JWT habilitada');
    }

    const envPath = path.join(process.cwd(), '.env');
    const envContent = fs.readFileSync(envPath, 'utf8');
    const dbType = envContent.includes('DB_TYPE=sqlsrv') ? 'sqlsrv' : 'mysql';

    // Crear migración
    write(process.cwd(), 'database/migrations/password_resets.sql', t.passwordResetMigration(dbType));
    success('Creado: database/migrations/password_resets.sql');

    // Crear modelo
    write(process.cwd(), 'app/Models/PasswordResetModel.php', t.passwordResetModel);
    success('Creado: app/Models/PasswordResetModel.php');

    // Actualizar AuthController
    const authControllerPath = path.join(process.cwd(), 'app/Controllers/AuthController.php');
    if (exists(authControllerPath)) {
        let authController = fs.readFileSync(authControllerPath, 'utf8');
        
        // Agregar use statement
        if (!authController.includes('use App\\Models\\PasswordResetModel')) {
            authController = authController.replace(
                'use App\\Models\\UserModel;',
                'use App\\Models\\PasswordResetModel;\nuse App\\Models\\UserModel;'
            );
        }

        // Agregar propiedad
        if (!authController.includes('private PasswordResetModel $passwordResetModel')) {
            authController = authController.replace(
                'private RefreshTokenModel $refreshTokenModel;',
                'private RefreshTokenModel $refreshTokenModel;\n    private PasswordResetModel $passwordResetModel;'
            );
        }

        // Agregar inicialización en constructor
        if (!authController.includes('$this->passwordResetModel = new PasswordResetModel()')) {
            authController = authController.replace(
                '$this->refreshTokenModel = new RefreshTokenModel();',
                '$this->refreshTokenModel = new RefreshTokenModel();\n        $this->passwordResetModel = new PasswordResetModel();'
            );
        }

        // Agregar métodos si no existen
        if (!authController.includes('public function forgotPassword()')) {
            const resetMethods = `

    public function forgotPassword()
    {
        try {
            $body = $this->getBody();
            $errors = Validator::validate($body, ['email' => 'required|email']);
            if (!empty($errors)) {
                Response::error('Errores de validación', 422, $errors);
            }

            $user = $this->userModel->findByEmail($body['email']);
            if (!$user) {
                // Por seguridad, siempre devolver éxito aunque el email no exista
                Response::success(null, 'Si el email existe, recibirás un enlace de recuperación');
            }

            $token = $this->passwordResetModel->createToken($body['email']);
            
            // TODO: Enviar email con el token
            // $resetLink = "https://tuapp.com/reset-password?token={$token}";
            // Email::send($body['email'], 'Password Reset', $resetLink);

            Logger::info('Token de recuperación generado', ['email' => $body['email']]);
            
            // En desarrollo, devolver el token para testing
            $response = ['message' => 'Token de recuperación generado'];
            if (getenv('APP_ENV') === 'development') {
                $response['token'] = $token; // Solo en desarrollo
            }

            Response::success($response);
        } catch (\\Exception $e) {
            Logger::error('Error en forgotPassword', ['exception' => $e]);
            Response::error('Error al procesar solicitud', 500);
        }
    }

    public function resetPassword()
    {
        try {
            $body = $this->getBody();
            $errors = Validator::validate($body, [
                'token' => 'required',
                'password' => 'required|min:6'
            ]);
            if (!empty($errors)) {
                Response::error('Errores de validación', 422, $errors);
            }

            $resetData = $this->passwordResetModel->findByToken($body['token']);
            if (!$resetData) {
                Response::error('Token inválido o expirado', 400);
            }

            $user = $this->userModel->findByEmail($resetData['email']);
            if (!$user) {
                Response::error('Usuario no encontrado', 404);
            }

            // Actualizar contraseña
            $hashedPassword = password_hash($body['password'], PASSWORD_BCRYPT);
            $this->userModel->update($user['id'], ['password' => $hashedPassword]);

            // Eliminar token usado
            $this->passwordResetModel->deleteByEmail($resetData['email']);

            Logger::info('Contraseña restablecida', ['user_id' => $user['id']]);

            Response::success(null, 'Contraseña restablecida correctamente');
        } catch (\\Exception $e) {
            Logger::error('Error en resetPassword', ['exception' => $e]);
            Response::error('Error al restablecer contraseña', 500);
        }
    }`;

            authController = authController.replace(/}\s*$/, resetMethods + '\n}');
        }

        fs.writeFileSync(authControllerPath, authController);
        success('Actualizado: app/Controllers/AuthController.php');
    }

    // Actualizar rutas
    const routesPath = path.join(process.cwd(), 'app/Routes/web.php');
    if (exists(routesPath)) {
        let routes = fs.readFileSync(routesPath, 'utf8');
        
        if (!routes.includes('/auth/forgot-password')) {
            const resetRoutes = `$router->post('/auth/forgot-password', 'AuthController', 'forgotPassword');
                                $router->post('/auth/reset-password', 'AuthController', 'resetPassword');`;
            routes = routes.replace(
                "$router->post('/auth/login', 'AuthController', 'login');",
                "$router->post('/auth/login', 'AuthController', 'login');\n" + resetRoutes
            );
            fs.writeFileSync(routesPath, routes);
            success('Actualizado: app/Routes/web.php');
        }
    }

    console.log('\n📝 Próximos pasos:');
    console.log('   1. Ejecuta: php-init db:migrate');
    console.log('   2. Implementa el envío de emails en AuthController::forgotPassword()');
    console.log('\n📬 Endpoints creados:');
    console.log('   POST /auth/forgot-password - Solicitar recuperación');
    console.log('   POST /auth/reset-password - Restablecer contraseña\n');
}

async function initDocker() {
    if (!inProject()) error('No estás en un proyecto.');

    const envPath = path.join(process.cwd(), '.env');
    const envContent = fs.readFileSync(envPath, 'utf8');
    const dbType = envContent.includes('DB_TYPE=sqlsrv') ? 'sqlsrv' : 'mysql';

    write(process.cwd(), 'docker-compose.yml', t.dockerCompose(dbType));
    success('Creado: docker-compose.yml');

    write(process.cwd(), 'Dockerfile', t.dockerfile);
    success('Creado: Dockerfile');

    write(process.cwd(), '.dockerignore', t.dockerignore);
    success('Creado: .dockerignore');

    console.log('\n🐳 Docker configurado exitosamente!');
    console.log('\n📝 Próximos pasos:');
    console.log('   1. docker-compose up -d');
    console.log('   2. docker-compose exec app composer install');
    console.log('   3. docker-compose exec app php-init db:migrate');
    console.log('\n🌐 La aplicación estará en: http://localhost:8000\n');
}

// ==============================
// CLI
// ==============================

program
    .command('new <nombre>')
    .description('Crea un nuevo proyecto PHP MVC')
    .option('--database <type>', 'Tipo de base de datos (mysql o sqlsrv)')
    .option('--jwt', 'Incluir autenticación JWT')
    .option('--db-host <host>', 'Host de la base de datos')
    .option('--db-port <port>', 'Puerto de la base de datos')
    .option('--db-name <name>', 'Nombre de la base de datos')
    .option('--db-user <user>', 'Usuario de la base de datos')
    .option('--db-pass <pass>', 'Contraseña de la base de datos')
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

program.command('db:migrate')
    .description('Ejecuta las migraciones de la base de datos')
    .action(runMigrations);

program.command('db:fresh')
    .description('Elimina la base de datos y ejecuta todas las migraciones')
    .option('-f, --force', 'Forzar sin confirmación (usar con precaución)')
    .action(dbFresh);

program.command('make:auth-reset')
    .description('Genera sistema de recuperación de contraseña')
    .action(makeAuthReset);

program.command('init:docker')
    .description('Genera archivos Docker (Dockerfile, docker-compose.yml)')
    .action(initDocker);

program.parse(process.argv);
