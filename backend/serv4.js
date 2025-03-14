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

db.getConnection((err) => {
  if (err) {
    console.error("Error al conectar con la base de datos:", err);
    return;
  }
  console.log("Conexión a la base de datos establecida.");
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
const uploadsDir = path.join(__dirname, '..', 'uploads'); 
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}


// Rutas existentes de autenticación
app.use('/uploads', express.static(path.join(__dirname, '..', 'uploads')));


const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);  // Asegura que apunta a la ubicación correcta
  },
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
app.post("/api/register", async (req, res) => {
  const { name, email, password, gender, birthdate } = req.body;

  try {
    const query = "SELECT * FROM users WHERE email = ?";
    db.query(query, [email], async (err, results) => {
      if (err) {
        console.error("Error al verificar el correo:", err);
        return res.status(500).json({ message: "Error interno del servidor." });
      }

      if (results && results.length > 0) {
        return res
          .status(409)
          .json({ message: "El correo ya está registrado." });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const insertQuery =
          "INSERT INTO users (name, email, password, gender, birthdate) VALUES (?, ?, ?, ?, ?)";
        db.query(
          insertQuery,
          [name, email, hashedPassword, gender, birthdate],
          (err) => {
            if (err) {
              console.error("Error al registrar al usuario:", err);
              return res
                .status(500)
                .json({ message: "Error al registrar al usuario." });
            }
            res.status(201).json({ message: "Usuario registrado con éxito." });
          }
        );
      } catch (hashError) {
        console.error("Error al encriptar la contraseña:", hashError);
        res.status(500).json({ message: "Error interno del servidor." });
      }
    });
  } catch (outerError) {
    console.error("Error inesperado:", outerError);
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const query = "SELECT * FROM users WHERE email = ?";
    db.query(query, [email], async (err, results) => {
      if (err) {
        console.error("Error al buscar al usuario:", err);
        return res.status(500).send("Error al buscar al usuario.");
      }

      if (results.length === 0) {
        return res.status(404).send("Usuario no encontrado.");
      }

      const isPasswordMatch = await bcrypt.compare(
        password,
        results[0].password
      );
      if (!isPasswordMatch) {
        return res.status(401).send("Contraseña incorrecta.");
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
    res.status(500).json({ message: "Error interno del servidor." });
  }
});

// Nuevas rutas para administración
app.get("/api/users", (req, res) => {
  db.query("SELECT * FROM users ORDER BY id", (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.get("/api/users/search", (req, res) => {
  const { type, value } = req.query;
  let query =
    type === "id"
      ? "SELECT * FROM users WHERE id = ?"
      : `SELECT * FROM users WHERE ${type} LIKE ?`;
  db.query(query, [type === "id" ? value : `%${value}%`], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.post("/api/users", async (req, res) => {
  const { name, email, password, gender, birthdate } = req.body;

  try {
    // Primero verificar si el email ya existe
    const [existingUsers] = await db
      .promise()
      .query("SELECT id FROM users WHERE email = ?", [email]);

    if (existingUsers.length > 0) {
      return res.status(409).json({
        message: "El email ya está registrado en el sistema.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await db
      .promise()
      .query(
        "INSERT INTO users (name, email, password, gender, birthdate) VALUES (?, ?, ?, ?, ?)",
        [name, email, hashedPassword, gender, birthdate]
      );

    res.status(201).json({
      id: result.insertId,
      name,
      email,
      gender,
      birthdate,
    });
  } catch (error) {
    console.error("Error al crear usuario:", error);
    res.status(500).json({ message: "Error al crear el usuario." });
  }
});

app.put("/api/users/:id", async (req, res) => {
  const { id } = req.params;
  const { name, email, password, gender, birthdate } = req.body;

  try {
    // Verificar si el email ya está en uso por otro usuario
    const [existingEmails] = await db
      .promise()
      .query("SELECT id FROM users WHERE email = ? AND id != ?", [email, id]);

    if (existingEmails.length > 0) {
      return res.status(409).json({ message: "Email ya está en uso." });
    }

    // Construir la consulta según si hay nueva contraseña o no
    let query, updateFields;

    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      query =
        "UPDATE users SET name = ?, email = ?, password = ?, gender = ?, birthdate = ? WHERE id = ?";
      updateFields = [name, email, hashedPassword, gender, birthdate, id];
    } else {
      query =
        "UPDATE users SET name = ?, email = ?, gender = ?, birthdate = ? WHERE id = ?";
      updateFields = [name, email, gender, birthdate, id];
    }

    await db.promise().query(query, updateFields);
    res.json({ id, name, email, gender, birthdate });
  } catch (error) {
    console.error("Error en la actualización:", error);
    res.status(500).json({ error: error.message });
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

   app.delete("/api/users/:id", (req, res) => {
    const { id } = req.params;
  
    // Posibles extensiones de la foto de perfil
    const possibleExtensions = ['.jpg', '.jpeg', '.png'];
    let fileFound = false;
  
    // Intentar encontrar y eliminar el archivo de la foto de perfil
    for (const ext of possibleExtensions) {
      const filePath = path.join(__dirname, '..', 'uploads', `user-${id}${ext}`);
      if (fs.existsSync(filePath)) {
        try {
          fs.unlinkSync(filePath);  // Elimina el archivo si existe
          fileFound = true;
          break;
        } catch (err) {
          console.error("Error al eliminar la foto de perfil:", err);
        }
      }
    }
  
    if (!fileFound) {
      console.warn(`No se encontró la foto de perfil para el usuario con ID ${id}`);
    }
  
    // Eliminar la fila del usuario en la base de datos
    db.query("DELETE FROM users WHERE id = ?", [id], (err) => {
      if (err) return res.status(500).json({ error: err.message });
  
      res.json({ message: "Usuario y foto de perfil eliminados exitosamente" });
    });
  });

app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});
