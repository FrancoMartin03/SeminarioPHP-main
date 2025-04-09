<?php

namespace App\models;

require_once __DIR__ . '/../models/DB.php';
use App\models\DB; //importar la clase DB para la conexion con la base de datos
use PDO; //importa clase para la conexion con la DB
use PDOException; //importa la clase PDOException para manejar errores de la base de datos
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class User {

    // obtener clave secreta desde variables de entorno para manejar los tokens
    public static function getSecretKey() {
        return $_ENV['JWT_SECRET'] ?? 'clave_por_defecto';
    }

    // verificar credenciales del usuario
    public static function verificarCredenciales($nombre, $usuario, $password) {
        try {
            $db = DB::getConnection();
            $query = "SELECT * FROM usuario WHERE usuario = :usuario";
            $stmt = $db->prepare($query); //variable que reprenseta la consulta preparada
            $stmt->bindParam(":usuario", $usuario); //asocia los valores
            $stmt->execute(); //ejecuta la consulta 

            $user = $stmt->fetch(PDO::FETCH_ASSOC); //recupera la consulta en un arreglo, si no hay resultado es false 

            if ($user && password_verify($password, $user['password'])) { //compara las contrasenias
                return $user;
            }
            return false;
        } catch (PDOException $e) {
            error_log("Error en verificarCredenciales: " . $e->getMessage());
            return false;
        }
    }

    // guardar el token de autenticación en la base de datos
    public static function guardarToken($usuario, $token, $expiracion) {
        try {
            $db = DB::getConnection();
            $query = "UPDATE usuario SET token = :token, vencimiento_token = :expiracion WHERE usuario = :usuario";
            $stmt = $db->prepare($query);
            $stmt->bindParam(":token", $token);
            $stmt->bindParam(":expiracion", $expiracion);
            $stmt->bindParam(":usuario", $usuario);
            return $stmt->execute();
        } catch (PDOException $e) {
            error_log("Error en guardarToken: " . $e->getMessage());
            return false;
        }
    }

    // validar datos antes de crear un usuario
    public static function validarDatos($usuario, $password) {
        if (!preg_match('/^[a-z A-Z 0-9]{6,20}$/', $usuario)) {
            return "El usuario debe tener entre 6 y 20 caracteres alfanuméricos.";
        }

        if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/', $password)) {
            return "La clave debe tener al menos 8 caracteres, incluir mayusculas, minusculas, numeros y un caracter especial.";
        }

        return null; 
    }

    // 🔹 Crear un nuevo usuario
    public static function crearUsuario($nombre, $usuario, $password) {
        try {
            $db = DB::getConnection(); 

            $error = self::validarDatos($usuario, $password);
            if ($error) {
                return $error;
            }

            // verificar si el usuario ya existe
            $stmt = $db->prepare("SELECT id FROM usuario WHERE usuario = :usuario");
            $stmt->execute([':usuario' => $usuario]);

            if ($stmt->rowCount() > 0) {
                return "El usuario ya está en uso.";
            }

            // Cifrar contraseña y registrar usuario
            $claveHash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $db->prepare("INSERT INTO usuario (nombre, usuario, password) VALUES (:nombre, :usuario, :password)");
            $exito = $stmt->execute([
                ':nombre' => $nombre,
                ':usuario' => $usuario,
                ':password' => $claveHash
            ]);

            return $exito ? true : "Error al crear el usuario.";
        } catch (PDOException $e) {
            error_log("Error en crearUsuario: " . $e->getMessage());
            return "Error al crear el usuario.";
        }
    }


    // 🔹 Obtener el token de un usuario

    public static function obtenerInformacionPorUsuario($usuario){
        try{
            $db= DB::getConnection();
            $query="SELECT id, nombre, usuario FROM usuario WHERE usuario = :usuario";
            $stmt=$db->prepare($query);
            $stmt->bindParam(':usuario',$usuario);
            $stmt->execute();
            
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return $user ?: null; // Retorna null si no se encuentra el usuario
    
        } catch (PDOException $e){
            error_log("Error al obtener informacion del usuario: " . $e->getMessage());
            return null;
        }
        }


    // 🔹 Actualizar informaacion del usuario
    
    public static function cambiarInfo($usuario,$nombre,$password){
        try{
            $db= DB::getConnection();
            // Obtener los datos actuales del usuario
            $query = "SELECT nombre, password FROM usuario WHERE usuario = :usuario";
            $stmt = $db->prepare($query);
            $stmt->bindParam(':usuario', $usuario);
            $stmt->execute();

            $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            return "Usuario no encontrado.";
        }

        // Verificar si los datos enviados son iguales a los actuales
        if ($user['nombre'] === $nombre && password_verify($password, $user['password'])) {
            return "No se realizaron cambios porque los datos enviados son iguales a los existentes.";
        }

            //verificar que la contraseña nueva es valida
            if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/', $password)) {
                return "Contrasenia invalida. Debe tener al menos 8 caracteres, incluir mayusculas, minusculas, numeros y un caracter especial.";
            }

            //cifrar contraseña
            $claveHash= password_hash($password, PASSWORD_DEFAULT);

            //actualizar informacion
            $query="UPDATE usuario SET nombre = :nombre, password = :password WHERE usuario = :usuario";
            $stmt=$db->prepare($query);
            $stmt->bindParam(':nombre',$nombre);
            $stmt->bindParam(':password',$claveHash);
            $stmt->bindParam(':usuario',$usuario);
            $stmt->execute();

            if($stmt->rowCount() > 0)  {
                return true;
            } else {
                return "No se realizaron cambios en la informacion.";
            }
        }catch(PDOException $e){
            error_log("Error en cambiarInfo: " . $e->getMessage());
            return "Error al actualizar la informacion del usuario.";
        }
}
}