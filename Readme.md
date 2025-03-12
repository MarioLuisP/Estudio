

# 🥖 Bakesoft - Ecommerce para Panaderías

### 📌 **Descripción del Proyecto**  
Bakesoft es una plataforma de e-commerce flexible y personalizable, diseñada específicamente para panaderías. Permite gestionar la compra y venta de productos en línea de manera sencilla y eficiente.

Cuenta con dos roles principales:  
- **Administrador**: gestiona productos, precios y stock.  
- **Cliente**: navega por el catálogo, realiza pedidos y efectúa compras.

Para la presentación del proyecto, personalizamos **Bakesoft** con la **Panadería La Macarena**, demostrando su capacidad de adaptación a distintos negocios del rubro.

### 🚀 **Metodología y Herramientas**
- **Metodología**: Scrum  
- **Gestión**: Jira  
- **Repositorio**: [GitHub](#)  
- **Despliegue**: Render | AWS  

---

## 👥 **Equipo del Proyecto**
- **QA**: Claudia Sánchez, Mario Passalia  
- **Backend**: Bruno Ortuño, Anibal Elbaum  
- **Frontend**: Germán Álvarez, Jesús Soto  

---

## 🛠️ **Tecnologías Utilizadas**
### 🔹 Backend (Java - Spring Boot)  
- Spring Web  
- Spring Security  
- Spring Data JPA  
- JUnit, Mockito (Testing)  
- Documentación API con Swagger  
- Configuración en `application.properties` o `application.yml`  
- Manejo de variables de entorno  

### 🔹 Base de Datos  
- MySQL  

### 🔹 Frontend (React + TypeScript)  
- Arquitectura Hexagonal  
  - **Dominio**: Modelos, casos de uso y lógica de negocio  
  - **Adaptadores**: Interfaces para interactuar con APIs  
  - **UI/Infraestructura**: Componentes de presentación, rutas y configuración  
- Librerías clave: `react-router-dom`, `axios`  
- Herramientas de calidad: ESLint, Prettier  
- Pruebas: Jest, React Testing Library  

---

## 🔑 **Gestión de Usuarios**
- **Inicio de Sesión**: Autenticación con correo y contraseña.  
- **Registro de Usuario**: Creación de cuenta con información básica.  
- **Control de Acceso**: Restricción de funciones según rol (Admin/Cliente).  

---

## 🛍️ **Gestión de Productos y Compras**
### 📦 **Administración de Productos (Solo Admin)**
- Registro de productos con nombre, descripción, precio, imágenes.  
- Atributos opcionales: descuentos y promociones.  
- Edición y eliminación de productos.  

### 🔎 **Exploración y Filtros**
- Lista de productos con detalles clave.  
- Filtros interactivos (descuentos, promociones).  
- Búsqueda por nombre o categoría.  

### 🛒 **Carrito de Compras**
- Botón "Agregar al carrito" en cada producto.  
- Lista persistente en sesión o base de datos.  
- Carrito temporal si el usuario no está autenticado.  

### 💳 **Proceso de Compra**
- Finalización segura del pedido.  
- Integración con pasarelas de pago.  

---

## 📊 **Dashboard y Gestión de Pedidos**
- **Clientes**: Historial de compras y favoritos.  
- **Administradores**: Panel para gestionar pedidos y usuarios.  
- Información actualizada en tiempo real.  

---
