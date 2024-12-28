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
app.post('/register', async (req, res) => {
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

app.post('/login', async (req, res) => {
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
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query(
        'INSERT INTO users (name, email, password, gender, birthdate) VALUES (?, ?, ?, ?, ?)',
        [name, email, hashedPassword, gender, birthdate],
        (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: result.insertId, ...req.body });
        }
    );
});

app.put('/api/users/:id', async (req, res) => {
    const { id } = req.params;
    const { name, email, password, gender, birthdate } = req.body;
    const hashedPassword = password ? await bcrypt.hash(password, 10) : null;
    
    const updateFields = password 
        ? [name, email, hashedPassword, gender, birthdate, id]
        : [name, email, gender, birthdate, id];
        
    const query = password
        ? 'UPDATE users SET name = ?, email = ?, password = ?, gender = ?, birthdate = ? WHERE id = ?'
        : 'UPDATE users SET name = ?, email = ?, gender = ?, birthdate = ? WHERE id = ?';

    db.query(query, updateFields, (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id, name, email, gender, birthdate });
    });
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