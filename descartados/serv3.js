const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const cors = require("cors");
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const app = express();
const port = 3000;

const db = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "Android",
  database: "user_registration",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

app.use(cors({
  origin: ["http://127.0.0.1:5500", "http://localhost:5500"],
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

app.use('/uploads', express.static('uploads'));

const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => {
    const userId = req.body.id;
    const ext = path.extname(file.originalname);
    cb(null, `user-${userId}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!allowedTypes.includes(file.mimetype)) {
      cb(new Error('Formato de archivo no permitido.'));
      return;
    }
    cb(null, true);
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const query = "SELECT * FROM users WHERE email = ?";
    db.query(query, [email], async (err, results) => {
      if (err) {
        console.error("Error al buscar al usuario:", err);
        return res.status(500).send("Error en el servidor.");
      }

      if (results.length === 0) {
        return res.status(401).send("Email o contraseña incorrectos.");
      }

      const isPasswordMatch = await bcrypt.compare(password, results[0].password);
      if (!isPasswordMatch) {
        return res.status(401).send("Email o contraseña incorrectos.");
      }

      res.status(200).json({
        message: "Inicio de sesión exitoso.",
        user: {
          id: results[0].id,
          name: results[0].name,
          email: results[0].email,
        },
      });
    });
  } catch (err) {
    console.error("Error durante el inicio de sesión:", err);
    res.status(500).send("Error interno del servidor.");
  }
});

app.put('/api/upload-photo', (req, res) => {
    // Convertimos el ID a string antes de procesar el archivo
    console.log("ID recibido:", req.body.id); // Debugging
   
    const storage = multer.diskStorage({
      destination: uploadsDir,
      filename: function(req, file, cb) {
        // Accedemos al ID desde la URL
        const id = new URLSearchParams(req.url.split('?')[1]).get('id');
        const ext = path.extname(file.originalname);
        cb(null, `user-${id}${ext}`);
      }
    });
   
    const upload = multer({ storage }).single('photo');
   
    upload(req, res, function(err) {
      if (err) return res.status(400).send(err.message);
      
      const id = new URLSearchParams(req.url.split('?')[1]).get('id');
      
      if (!id) return res.status(400).send('ID required');
      
      const relativePath = path.relative(__dirname, req.file.path).replace(/\\/g, '/');
      db.query('UPDATE users SET photo = ? WHERE id = ?', [relativePath, id], (err) => {
        if (err) {
          fs.unlinkSync(req.file.path);
          return res.status(500).send('Error saving photo');
        }
        res.status(200).send('Success');
      });
    });
   });

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});