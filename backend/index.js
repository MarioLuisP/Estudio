// server.js
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt'); // Importa bcrypt
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const port = 3000;

// Configuración de la base de datos
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Android',
  database: 'user_registration',
});

// Conexión a la base de datos
db.connect((err) => {
  if (err) {
    console.error('Error al conectar con la base de datos:', err);
    return;
  }
  console.log('Conexión a la base de datos establecida.');
});

// Middleware
app.use(bodyParser.json());
app.use(cors({
  origin: 'http://127.0.0.1:5500',
}));

// Ruta para registrar un usuario
app.post('/register', async (req, res) => {
  const { name, email, password, gender, birthdate } = req.body;

  try {
    // Encriptar la contraseña
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insertar el usuario en la base de datos
    const query = `
      INSERT INTO users (name, email, password, gender, birthdate)
      VALUES (?, ?, ?, ?, ?)
    `;
    db.query(
      query,
      [name, email, hashedPassword, gender, birthdate],
      (err, result) => {
        if (err) {
          console.error('Error al registrar al usuario:', err);
          res.status(500).json({ message: 'Error al registrar al usuario.' });
          return;
        }
        res.status(201).json({ message: 'Usuario registrado con éxito.' });
      }
    );
  } catch (err) {
    console.error('Error al encriptar la contraseña:', err);
    res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

// Ruta para iniciar sesión
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Buscar al usuario por email
    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], async (err, results) => {
      if (err) {
        console.error('Error al buscar al usuario:', err);
        res.status(500).send('Error al buscar al usuario.');
        return;
      }

      if (results.length === 0) {
        res.status(404).send('Usuario no encontrado.');
        return;
      }

      const user = results[0];

      // Comparar la contraseña ingresada con el hash almacenado
      const isPasswordMatch = await bcrypt.compare(password, user.password);

      if (!isPasswordMatch) {
        res.status(401).send('Contraseña incorrecta.');
        return;
      }

      res.status(200).send('Inicio de sesión exitoso.');
    });
  } catch (err) {
    console.error('Error durante el inicio de sesión:', err);
    res.status(500).send('Error interno del servidor.');
  }
});

// Iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});
