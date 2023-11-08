import express from "express";
import mysql from "mysql";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";

const app = express();
app.use(
  cors({
    origin: ["http://localhost:3000"],
    methods: ["POST", "GET", "PUT", "DELETE"],
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

const con = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "signup",
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public/images");
  },
  filename: (req, file, cb) => {
    cb(
      null,
      file.fieldname + "_" + Date.now() + path.extname(file.originalname)
    );
  },
});

const upload = multer({
  storage: storage,
});

con.connect((err) => {
  if (err) {
    console.log("Error in connection");
  } else {
    console.log("DB connection established");
  }
});

const verifyUser = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res
      .status(401)
      .json({ Status: "Error", Message: "you are not authorized" });
  } else {
    jwt.verify(token, "jwt-secret-key", (err, decoded) => {
      if (err)
        return res
          .status(401)
          .json({ Status: "Error", Message: "Wrong token" });
      req.role = decoded.role;
      req.id = decoded.id;
      next();
    });
  }
};

// DASHBOARD CONTROLLER

app.get("/dashboard", verifyUser, (req, res) => {
  return res.status(200).json({
    Status: "Success",
    Message: "You are authenticated",
    role: req.role,
    id: req.id,
  });
});

// LOGIN CONTROLLER

app.post("/login", (req, res) => {
  const sql = "SELECT * FROM users Where email = ? AND password = ?";
  con.query(sql, [req.body.email, req.body.password], (err, result) => {
    if (err) {
      return res
        .status(400)
        .json({ Status: "Error", Message: "Error in running query" });
    }
    if (result.length > 0) {
      const token = jwt.sign({ role: "admin" }, "jwt-secret-key", {
        expiresIn: "1d",
      });
      res.cookie("token", token);

      const data = {
        id: result[0].id,
        name: result[0].name,
        gender: result[0].gender,
        email: result[0].email,
        role: result[0].role,
      };

      return res.status(200).json({
        Status: "Success",
        Message: "Login successful",
        Result: data,
        permit: "admin",
      });
    } else {
      return res
        .status(401)
        .json({ Status: "Error", Message: "Wrong email or password" });
    }
  });
});

// LOGOUT CONTROLLER

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.status(200).json({ Status: "Success", Message: "logout successful" });
});

// EMPLOYEE LOGIN CONTROLLER

app.post("/employeeLogin", (req, res) => {
  console.log(req.body);
  const sql = "SELECT * FROM employees WHERE email = ?";
  con.query(sql, [req.body.email], (err, result) => {
    if (err) {
      return res
        .status(400)
        .json({ Status: "Error", Message: "Error in running query" });
    }

    if (result.length > 0) {
      const user = result[0];
      bcrypt.compare(req.body.password, user.password, (err, passwordMatch) => {
        if (err) {
          return res
            .status(401)
            .json({ Status: "Error", Message: "Password doesn't match" });
        }

        if (passwordMatch) {
          const token = jwt.sign(
            { role: "employee", id: user.id },
            "jwt-secret-key",
            {
              expiresIn: "1d",
            }
          );
          res.cookie("token", token);
          return res.status(200).json({
            Status: "Success",
            Message: "Login successful",
            id: user.id,
            permit: "employee",
          });
        } else {
          return res
            .status(401)
            .json({ Status: "Error", Message: "Wrong email or password" });
        }
      });
    } else {
      return res
        .status(401)
        .json({ Status: "Error", Message: "Wrong email or password" });
    }
  });
});

// ADD EMPLOYEE CONTROLLER

app.post("/create", upload.single("image"), (req, res) => {
  const sql =
    "INSERT INTO employees (`name`, `email`, `password`, `address`, `salary`, `image`) VALUES (?)";
  bcrypt.hash(req.body.password.toString(), 10, (err, hash) => {
    if (err) return res.json({ Error: "Error in hashing password" });

    const values = [
      req.body.name,
      req.body.email,
      hash,
      req.body.address,
      req.body.salary,
      req.file.filename,
    ];

    con.query(sql, [values], (err, result) => {
      if (err) {
        return res
          .status(400)
          .json({ Status: "Error", Message: "Error inside query" });
      }

      return res
        .status(200)
        .json({ Status: "Success", Message: "Employee added successfully" });
    });
  });
});

// UPDATE EMPLOYEE CONTROLLER

app.put("/update/:id", (req, res) => {
  const { id } = req.params;
  const sql =
    "UPDATE employees SET name = ? , email = ?, address = ?, salary = ? WHERE id = ?";

  const values = [
    req.body.name,
    req.body.email,
    req.body.address,
    req.body.salary,
  ];

  con.query(sql, [...values, id], (err, result) => {
    if (err) {
      return res
        .status(400)
        .json({ Status: "Error", Message: "Error inside query" });
    }

    return res
      .status(200)
      .json({ Status: "Success", Message: "Employee updated successfully" });
  });
});

// GET ALL ADMINS CONTROLLER

app.get("/getAdmins", (req, res) => {
  const sql = "SELECT * FROM users";
  con.query(sql, (err, result) => {
    if (err) {
      return res
        .status(400)
        .json({ Status: "Error", Message: "Error inside sql query" });
    }

    return res.status(200).json({ Status: "Success", Result: result });
  });
});

// GET EMPLOYEES CONTROLLER

app.get("/getEmployees", (req, res) => {
  const sql = "SELECT * FROM employees";
  con.query(sql, (err, result) => {
    if (err) {
      return res
        .status(400)
        .json({ Status: "Error", Message: "Error inside sql query" });
    }

    return res.status(200).json({ Status: "Success", Result: result });
  });
});

// GET SINGLE EMPLOYEE CONTROLLER

app.get("/getEmployee/:id", (req, res) => {
  const sql = "SELECT * FROM employees WHERE id = ?";
  const { id } = req.params;

  con.query(sql, [id], (err, result) => {
    if (err) {
      return res
        .status(400)
        .json({ Status: "Error", Message: "Error inside sql query" });
    }

    return res.status(200).json({ Status: "Success", Result: result });
  });
});

// DELETE AN EMPLOYEE CONTROLLER

app.delete("/deleteEmployee/:id", (req, res) => {
  const { id } = req.params;
  const sql = "DELETE FROM employees WHERE id = ?";

  con.query(sql, [id], (err, result) => {
    if (err) {
      return res
        .status(400)
        .json({ Status: "Error", Message: "Error inside query" });
    }

    return res
      .status(200)
      .json({ Status: "Success", Message: "Employee deleted successfully" });
  });
});

// COUNT ADMIN CONTROLLER

app.get("/adminCount", (req, res) => {
  const sql = "SELECT count(id) as admin from users";

  con.query(sql, (err, result) => {
    if (err) {
      return res
        .status(400)
        .json({ Status: "Error", Message: "Error in query" });
    }

    return res.status(200).json({ Status: "Success", Result: result });
  });
});

// COUNT EMPLOYEES CONTROLLER

app.get("/employeeCount", (req, res) => {
  const sql = "SELECT count(id) as employee from employees";

  con.query(sql, (err, result) => {
    if (err) {
      return res
        .status(400)
        .json({ Status: "Error", Message: "Error in query" });
    }

    return res.status(200).json({ Status: "Success", Result: result });
  });
});

// SUM OF SALARIES CONTROLLER

app.get("/sumSalary", (req, res) => {
  const sql = "SELECT sum(salary) as sumOfSalary from employees";

  con.query(sql, (err, result) => {
    if (err) {
      return res
        .status(400)
        .json({ Status: "Error", Message: "Error in query" });
    }

    return res.status(200).json({ Status: "Success", Result: result });
  });
});

app.listen(5000, () => {
  console.log("Server started on port 5000");
});
