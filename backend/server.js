const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const port = 3000;

const db = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'Android',
  database: 'user_registration',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

db.getConnection((err) => {
  if (err) {
    console.error('Error al conectar con la base de datos:', err);
    return;
  }
  console.log('Conexión a la base de datos establecida.');
});

app.use(bodyParser.json());
app.use(cors({
  origin: ['http://127.0.0.1:5500', 'http://localhost:5500'],
}));

// Rutas existentes de autenticación
app.post('/api/register', async (req, res) => {
  const { name, email, password, gender, birthdate } = req.body;

  try {
    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], async (err, results) => {
      if (err) {
        console.error('Error al verificar el correo:', err);
        return res.status(500).json({ message: 'Error interno del servidor.' });
      }

      if (results && results.length > 0) {
        return res.status(409).json({ message: 'El correo ya está registrado.' });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const insertQuery = 'INSERT INTO users (name, email, password, gender, birthdate) VALUES (?, ?, ?, ?, ?)';
        db.query(insertQuery, [name, email, hashedPassword, gender, birthdate], (err) => {
          if (err) {
            console.error('Error al registrar al usuario:', err);
            return res.status(500).json({ message: 'Error al registrar al usuario.' });
          }
          res.status(201).json({ message: 'Usuario registrado con éxito.' });
        });
      } catch (hashError) {
        console.error('Error al encriptar la contraseña:', hashError);
        res.status(500).json({ message: 'Error interno del servidor.' });
      }
    });
  } catch (outerError) {
    console.error('Error inesperado:', outerError);
    res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], async (err, results) => {
      if (err) {
        console.error('Error al buscar al usuario:', err);
        return res.status(500).send('Error al buscar al usuario.');
      }

      if (results.length === 0) {
        return res.status(404).send('Usuario no encontrado.');
      }

      const isPasswordMatch = await bcrypt.compare(password, results[0].password);
      if (!isPasswordMatch) {
        return res.status(401).send('Contraseña incorrecta.');
      }

      res.status(200).send('Inicio de sesión exitoso.');
    });
  } catch (err) {
    console.error('Error durante el inicio de sesión:', err);
    res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

// Nuevas rutas para administración
app.get('/api/users', (req, res) => {
    db.query('SELECT * FROM users ORDER BY id', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.get('/api/users/search', (req, res) => {
    const { type, value } = req.query;
    let query = type === 'id' ? 'SELECT * FROM users WHERE id = ?' : `SELECT * FROM users WHERE ${type} LIKE ?`;
    db.query(query, [type === 'id' ? value : `%${value}%`], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.post('/api/users', async (req, res) => {
  const { name, email, password, gender, birthdate } = req.body;
  
  try {
      // Primero verificar si el email ya existe
      const [existingUsers] = await db.promise().query(
          'SELECT id FROM users WHERE email = ?',
          [email]
      );

      if (existingUsers.length > 0) {
          return res.status(409).json({ 
              message: 'El email ya está registrado en el sistema.' 
          });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const [result] = await db.promise().query(
          'INSERT INTO users (name, email, password, gender, birthdate) VALUES (?, ?, ?, ?, ?)',
          [name, email, hashedPassword, gender, birthdate]
      );

      res.status(201).json({ 
          id: result.insertId,
          name,
          email,
          gender,
          birthdate
      });
  } catch (error) {
      console.error('Error al crear usuario:', error);
      res.status(500).json({ message: 'Error al crear el usuario.' });
  }
});


app.put('/api/users/:id', async (req, res) => {
  const { id } = req.params;
  const { name, email, password, gender, birthdate } = req.body;

  try {
      // Verificar si el email ya está en uso por otro usuario
      const [existingEmails] = await db.promise().query(
          'SELECT id FROM users WHERE email = ? AND id != ?',
          [email, id]
      );

      if (existingEmails.length > 0) {
          return res.status(409).json({ message: 'Email ya está en uso.' });
      }

      // Construir la consulta según si hay nueva contraseña o no
      let query, updateFields;

      if (password) {
          const hashedPassword = await bcrypt.hash(password, 10);
          query = 'UPDATE users SET name = ?, email = ?, password = ?, gender = ?, birthdate = ? WHERE id = ?';
          updateFields = [name, email, hashedPassword, gender, birthdate, id];
      } else {
          query = 'UPDATE users SET name = ?, email = ?, gender = ?, birthdate = ? WHERE id = ?';
          updateFields = [name, email, gender, birthdate, id];
      }

      await db.promise().query(query, updateFields);
      res.json({ id, name, email, gender, birthdate });

  } catch (error) {
      console.error('Error en la actualización:', error);
      res.status(500).json({ error: error.message });
  }
});


app.delete('/api/users/:id', (req, res) => {
    const { id } = req.params;
    db.query('DELETE FROM users WHERE id = ?', [id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Usuario eliminado exitosamente' });
    });
});

app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});