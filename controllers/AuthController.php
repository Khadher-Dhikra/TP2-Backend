<?php
require_once "../config/database.php";
require_once "../models/User.php";

class AuthController {

    private $user;

    public function __construct() {
        $database = new Database();
        $db = $database->connect();
        $this->user = new User($db);
    }

    public function register($data) {
        if (!$data) {
            echo json_encode(["status" => "error", "message" => "Invalid JSON"]);
            return;
        }

        if ($this->user->emailExists($data["email"])) {
            echo json_encode(["status" => "error", "message" => "Email already exists"]);
            return;
        }

        $hashedPassword = password_hash($data["password"], PASSWORD_DEFAULT);

        if ($this->user->register($data["username"], $data["email"], $hashedPassword)) {
            echo json_encode(["status" => "success", "message" => "User registered"]);
        } else {
            echo json_encode(["status" => "error", "message" => "Registration failed"]);
        }
    }

    public function login($data) {
        if (!$data) {
            echo json_encode(["status" => "error", "message" => "Invalid JSON"]);
            return;
        }

        $user = $this->user->login($data["email"]);

        if (!$user) {
            echo json_encode(["status" => "error", "message" => "User not found"]);
            return;
        }

        if (password_verify($data["password"], $user["password"])) {
            echo json_encode([
                "status" => "success",
                "message" => "Login successful",
                "user" => [
                    "id" => $user["id"],
                    "username" => $user["username"],
                    "email" => $user["email"]
                ]
            ]);
        } else {
            echo json_encode(["status" => "error", "message" => "Incorrect password"]);
        }
    }
}