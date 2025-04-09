<?php

error_reporting(E_ALL);
ini_set('display_errors', 1);

//para manejar solicitudes http
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;

require_once __DIR__ . '/../controllers/UserController.php';
use App\Controllers\UserController;

require __DIR__ . '/../../vendor/autoload.php';


$app = AppFactory::create(); //crear una instancia de slim para manejar las rutas

// middleware para interceptar las solicitudes y respuestas, y asi validarlas o modificarlas
$app->addRoutingMiddleware();
$app->addBodyParsingMiddleware();
$app->addErrorMiddleware(true, true, true);


//endpoint de prueba hola mundo
$app->get('/', function (Request $request, Response $response, $args) {
    $response->getBody()->write("Hello world!");
    return $response;
});

// endpoint para login
//esto le dice a slim que cuando llega una solicitud POST /login llama al metodo login del usercontroller
$app->post('/login', UserController::class . ':login');

// Endpoint para registrar un usuario
//esto hace que cuando llegue una solicitud de POST /registro se llama al metodo register del usercontroller
$app->post('/registro', function (Request $request, Response $response) {
    $data = $request->getParsedBody(); //obtenemos los datos de la peticion
    $resultado = UserController::register($data); //se envian los datos al controloador 

    //respuesta
    $response->getBody()->write(json_encode(['message' => $resultado['mensaje'] ?? $resultado['error']]));
    //retorna la respuesta con el codigo correspondiente
    return $response->withStatus($resultado['status'])->withHeader('Content-Type', 'application/json');

});


//Endpoint para obtener la informacion del usuario
$app->get('/usuarios/{usuario}', function (Request $request, Response $response, array $args) {
    $usuario = $args['usuario']; // Obtener el nombre de usuario de la URL
    $token = $request->getHeader('Authorization')[0] ?? ''; // Obtener el token del encabezado
    $token = str_replace('Bearer ', '',$token); //saco el bearer del token(caracteres inservibles)
    $token = trim($token); //saco espacios en blanco
    $resultado = UserController::obtenerInformacionUsuario($usuario, $token);

    // Verificar la respuesta del controlador
    if ($resultado['status'] === 200) {
        $response->getBody()->write(json_encode($resultado['data']));
    } else {
        $response->getBody()->write(json_encode(['error' => $resultado['mensaje']]));
    }

    return $response->withHeader('Content-Type', 'application/json')->withStatus($resultado['status']);
});


//Endpoint para cambiar info de usuario logeado
$app->put('/usuarios/{usuario}', function (Request $request, Response $response, array $args ){
    //Extraigo la info para la consulta
    $usuario= $args['usuario'];
    $data=$request->getParsedBody();
    $token = $request->getHeader('Authorization')[0] ?? '';
    $token = str_replace('Bearer ', '',$token); //saco el bearer del token(caracteres inservibles)
    $token = trim($token); //saco espacios en blanco
    
    //llamo al controlador para actualizar la informacion
    $resultado=UserController::actualizarInformacion($usuario,$data,$token);

    //verifico la rta del controlador
    if($resultado['status']===200) $response->getBody()->write(json_encode($resultado['mensaje']));
    else $response->getBody()->write(json_encode(['error'=>$resultado['mensaje']]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus($resultado['status']);

});

$app->run()

?>