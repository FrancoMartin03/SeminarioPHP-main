<?php

namespace App\controllers;

require_once __DIR__ . '/../models/User.php';

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use App\models\User;
//generacion y validacion de tokens
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class UserController {
    //funciones para login
    public function login(Request $request, Response $response, array $args) {
        $data = $request->getParsedBody(); //obtiene los datos de la solicitud en json
        
        $nombre = $data['nombre'] ?? ''; //si no esta presente en $data le asigna ''
        $usuario = $data['usuario'] ?? '';
        $password = $data['password'] ?? '';
    
        //metodo de la clase User para chequear si las credenciales son correctas
        $user = User::verificarCredenciales($nombre, $usuario, $password);
    
        if ($user) { //si son correctas
            $expiracion = time() + 3600; // Token válido por 1 hora
    
            $payload = [
                "sub" => $user['id'],  
                "nombre" => $user['nombre'],
                "usuario" => $user['usuario'],
                "exp" => $expiracion
            ];

            // obtener la clave secreta desde config.php
            $config = require __DIR__ . '/../config/config.php';
            $jwt_secret = $config['jwt_secret'];
    
            $token = JWT::encode($payload, $jwt_secret, 'HS256'); //codifica el token con hs256
    
            User::guardarToken($usuario, $token, date('Y-m-d H:i:s', $expiracion));
            
            //si no hay problemas retorna el token en formato json con codigo 200 OK
            $response->getBody()->write(json_encode(["token" => $token]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
        } else { 
            $response->getBody()->write(json_encode(["error" => "Credenciales incorrectas"]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(401);
        }
    }

    //funciones para registro

    public static function register($data) {
        error_log(print_r($data, true)); 

        if (!isset($data['nombre'], $data['usuario'], $data['password'])) {
            return ['error' => 'Faltan datos obligatorios', 'status' => 400];
        }

        $resultado = User::crearUsuario($data['nombre'], $data['usuario'], $data['password']);

        if ($resultado === true) {
            return ['mensaje' => 'Usuario creado correctamente', 'status' => 200];
        }

        return ['error' => $resultado['mensaje'], 'status' => 400];
    }



    //funcion para mostrar informacion del usuario logeado
    public static function obtenerInformacionUsuario($usuario,$token){
       try{
        //validar token
        $secretKey = User::getSecretKey();
        $decode= JWT::decode($token, new Key($secretKey, 'HS256'));
        
        //verificar q el toquen no haya expirado
        if($decode -> exp < time()){
            return ['status'=>401, 'mensaje' => 'Token expirado'];
        }
        //obtener la informacion del usuario
        $userInfo = User::obtenerInformacionPorUsuario($usuario);


        if($userInfo){
            return ['status'=>200, 'data' => $userInfo];
        }
        else {
            return ['status'=>404, 'mensaje' => 'Usuario no encontrado'];
        }
    }catch (\Exception $e){
        return ['status'=>401, 'mensaje' =>'Token no autorizado'];
    }

        }



    //funcion  para cambiar info de usuario
    public static function actualizarInformacion($usuario, $data, $token){
        try{
        
        //validar token
        $secretKey = User::getSecretKey();
        $decode= JWT::decode($token, new Key($secretKey, 'HS256'));
        
        //verificar q el toquen no haya expirado
        if($decode -> exp < time()){
            return ['status'=>401, 'mensaje' => 'Token expirado'];
            
        }
        // Verificar que el usuario en el token coincida con el usuario solicitado(preguntar si es necesario)
        if ($decode->usuario !== $usuario) {
            return ['status' => 403, 'mensaje' => 'No tienes permiso para editar este usuario'];
        }
        //validar datos enviados
        if(!isset($data['nombre'], $data['password'])){
            return ['status'=>400, 'mensaje' =>'Faltan datos obligatorios'];
        }

        $resultado=User::cambiarInfo($usuario,$data['nombre'],$data['password']);
        if($resultado === true){
            return ['status'=> 200, 'mensaje'=>'Informacion actualizada.'];
        }
        else{
            return['status'=>400, 'mensaje'=>$resultado];
        }

    }catch(\Exception $e){
        return ['status' => 401, 'mensaje' => 'Token no autorizado'];
    }
}
}