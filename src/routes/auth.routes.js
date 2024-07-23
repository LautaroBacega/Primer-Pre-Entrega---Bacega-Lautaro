import { Router } from "express";
import { userModel } from "../daos/mongodb/models/user.model.js";
import { createHash } from "../utils/hash.js";
import { generateToken } from "../utils/jwt.js";
import passport from "passport";

const router = Router();

router.post(
    "/login",
    passport.authenticate("login", {
        session: false,
        failureRedirect: "/api/auth/login-error",
    }),
    async (req, res) => {
        const payload = {
            first_name: req.user.first_name,
            last_name: req.user.last_name,
            email: req.user.email,
            role: req.user.role,
    };

    const token = generateToken(payload);

    res.cookie("token", token, { httpOnly: true, maxAge: 100000 });

    res.status(200).json({
        message: "Autenticado",
        token,
    });
});

router.get('/login-error', (req, res) => {
    res.status(401).json({ message: "No autorizado" });
});

router.post("/register", async (req, res) => {
    const { first_name, last_name, email, age, role, password, cart } = req.body;

    if (!first_name || !last_name || !email || !age || !password || !cart) {
        return res.status(400).json({ message: "Faltan datos obligatorios" });
    }

    try {
        // Hasheamos la contraseña
        const hashPassword = await createHash(password);

        const user = await userModel.create({
            first_name,
            last_name,
            email,
            age,
            password: hashPassword,
            role,
            cart,
        });

        res.status(201).json(user);

    } catch (error) {
        res.status(500).json({ message: "Error al registrar usuario", details: error.message });
    }
});

router.get("/current", passport.authenticate("jwt", { session: false }), (req, res) => {
    res.status(200).json({
        message: "Bienvenido",
        user: req.user,
    });
});

export default router;