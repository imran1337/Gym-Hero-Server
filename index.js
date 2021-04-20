require("dotenv").config()
const express = require("express");
const app = express();
const port = process.env.PORT || 5000;
const MongoClient = require("mongodb").MongoClient;
const ObjectID = require("mongodb").ObjectID;
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const fileUpload = require("express-fileupload");

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(fileUpload());
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

//regexp validation
const emailRegexp = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
const userNameRegexp = /^(?=.{4,20}$)(?![_.])(?!.*[_.]{2})[a-zA-Z0-9._]+(?<![_.])$/;

//token secret
const secretKEY = process.env.JWT_SECRET_KEY;

//jwt token generate function
const createToken = async (userInfoData) => {
  const token = await jwt.sign(userInfoData, secretKEY);
  return token;
};

//jwt token verify
const verifyToken = async (userToken) => {
  try {
    const isValid = await jwt.verify(userToken, secretKEY);
    return isValid;
  } catch (verifyTokenError) {
    return false;
  }
};

app.get("/", (req, res) => {
  res.send("Something Went Wrong");
});

client.connect((err) => {
  const userCollection = client.db("gymClub").collection("user");
  const messageCollection = client.db("gymClub").collection("messages");
  const servicesCollection = client.db("gymClub").collection("services");
  const cartCollection = client.db("gymClub").collection("carts");
  const ordersCollection = client.db("gymClub").collection("orders");
  const reviewCollection = client.db("gymClub").collection("reviews");

  // signup user start
  app.post("/signup", async (req, res) => {
    const { userName, email, password, confirmPassword, name } = req.body;

    const userData = { name, userName, email, password };
    userData.role = "user";
    userData.createdAt = new Date();

    if (!emailRegexp.test(email)) {
      return res.status(400).send({ success: false, msg: '"Invalid Email"' });
    }

    if (!userNameRegexp.test(userName)) {
      return res
        .status(400)
        .send({ success: false, msg: '"Invalid User Name"' });
    }

    try {
      const isEmailPresent = await userCollection.findOne({ email });
      const isUserNamePresent = await userCollection.findOne({ userName });

      if (Boolean(isEmailPresent)) {
        return res
          .status(400)
          .send({ success: false, msg: "Email Already Registered" });
      }

      if (Boolean(isUserNamePresent)) {
        return res
          .status(400)
          .send({ success: false, msg: "Username Already Registered" });
      }

      const hashPass = await bcrypt.hash(password, 10);

      const saveUser = await userCollection.insertOne({
        ...userData,
        password: hashPass,
      });

      if (saveUser.insertedCount < 1) {
        return res.status(500).send("something went wrong");
      }

      const token = await createToken({ ...userData, password: undefined });

      return res.send({ success: true, token });
    } catch (signUpError) {
      console.log({ signUpError });
    }
  });
  // signup user end

  //login user start
  app.post("/login", async (req, res) => {
    const loginInfo = req.body;

    if (!userNameRegexp.test(loginInfo.userName)) {
      return res
        .status(400)
        .send({ success: false, msg: '"Invalid User Name"' });
    }

    const userName = { userName: loginInfo.userName };

    userCollection
      .findOne(userName)
      .then((isUser) => {
        if (isUser === null) {
          return res
            .status(404)
            .send({ success: false, msg: "user not found" });
        }

        bcrypt.compare(
          loginInfo.password,
          isUser.password,
          async (hashErr, hashRes) => {
            console.log({ hashRes }, { hashErr });
            if (hashRes) {
              //generate auth token
              const token = await createToken({
                ...isUser,
                password: undefined,
              });
              return res.send({ success: true, token });
            }
            return res
              .status(403)
              .send({ success: false, msg: "Invalid Password" });
          }
        );
      })
      .catch((findUsrErr) => console.log(findUsrErr));
  });
  //login user end

  //get user list start
  app.get("/users", async (req, res) => {
    const adminToken = req.headers.authorization;

    if (!adminToken.includes("Bearer ")) {
      return res.status(403).send("Unauthorized");
    }

    const token = adminToken.split(" ")[1];

    try {
      const isAdmin = await verifyToken(token);
      console.log(Boolean(isAdmin));

      if (!Boolean(isAdmin)) return res.status(403).send("Unauthorized");

      if (isAdmin.role !== "admin")
        return res.status(403).send("You have no permission to do that");

      userCollection.find({}).toArray((findError, usersResult) => {
        if (findError) return res.status(403).send(findError);
        res.send(usersResult);
      });
    } catch (error) {
      console.log(error);
    }
  });
  //get user list end

  //save contact us message start
  app.post("/send-message", (req, res) => {
    console.log(req.body);
    messageCollection
      .insertOne(req.body)
      .then((result) => {
        if (result.insertedCount) {
          return res.send({ success: true, message: "Submitted Successfully" });
        }
      })
      .catch((error) => {
        console.log(error);
      });
  });
  //save contact us message end

  //get messages start
  app.get("/get-messages", async (req, res) => {
    const adminToken = req.headers.authorization;

    if (!adminToken.includes("Bearer ")) {
      return res.status(403).send("Unauthorized");
    }

    const token = adminToken.split(" ")[1];

    try {
      const isAdmin = await verifyToken(token);
      console.log(Boolean(isAdmin));

      if (!Boolean(isAdmin)) return res.status(403).send("Unauthorized");

      if (isAdmin.role !== "admin")
        return res.status(403).send("You have no permission to do that");

      messageCollection.find({}).toArray((findError, usersResult) => {
        if (findError) return res.status(403).send(findError);
        res.send(usersResult);
      });
    } catch (error) {
      console.log(error);
    }
  });
  //get messages end

  //add services start

  app.post("/addService", async (req, res) => {
    try {
      const adminToken = req.headers.authorization;

      if (!adminToken.includes("Bearer ")) {
        return res.status(403).send("Unauthorized");
      }

      const token = adminToken.split(" ")[1];

      if (!req.files || Object.keys(req.files).length === 0) {
        return res.status(400).send("No files were uploaded.");
      }

      const image = { ...req.files.image };
      const imageName = await image.name.split(".");
      image.name = `imran_${Date.now()}.${imageName[1]}`;

      const serviceData = await { ...req.body, image };
      console.log(serviceData);

      const isAdmin = await verifyToken(token);
      console.log(Boolean(isAdmin));

      if (!Boolean(isAdmin)) return res.status(403).send("Unauthorized");

      if (isAdmin.role !== "admin")
        return res.status(403).send("You have no permission to do that");

      servicesCollection
        .insertOne(serviceData)
        .then((result) => {
          if (result.insertedCount) {
            res.send({ success: true, message: "Services Added Successfully" });
          }
        })
        .catch((serviceAddErr) => {
          res.status(500).send(serviceAddErr);
        });
    } catch (error) {
      console.log(error);
    }
  });

  //add services end

  // get services list start

  app.get("/get-services", async (req, res) => {
    const servicesWait = await servicesCollection.find({});
    servicesWait.toArray((error, services) => {
      if (error !== null) {
        return res.status(500).send("Something went wrong");
      }
      console.log(services);
      console.log("ssss");
      return res.send(services);
    });
  });

  // get services list end

  //delete service start

  app.delete("/deleteService/:_id", async (req, res) => {
    const { _id } = req.params;
    const adminToken = req.headers.authorization;

    if (!adminToken.includes("Bearer ")) {
      return res.status(403).send("Unauthorized");
    }

    const token = adminToken.split(" ")[1];

    try {
      const isAdmin = await verifyToken(token);
      console.log(Boolean(isAdmin));

      if (!Boolean(isAdmin)) return res.status(403).send("Unauthorized");

      if (isAdmin.role !== "admin")
        return res.status(403).send("You have no permission to do that");

      servicesCollection
        .findOneAndDelete({ _id: ObjectID(_id) })
        .then((data) => {
          res.send({
            success: true,
            message: "Services Removed Successfully",
          });
        })
        .catch((delError) => {
          res.status(500).send(delError);
        });
    } catch (error) {
      console.log(error);
    }
  });

  //delete service end

  // add to cart start
  app.post("/add-to-cart", async (req, res) => {
    const userToken = req.headers.authorization;
    const serviceData = req.body;
    console.log(serviceData);

    if (!userToken.includes("Bearer ")) {
      return res.status(403).send("Unauthorized");
    }

    const token = userToken.split(" ")[1];

    try {
      const isTokenValid = await verifyToken(token);
      console.log(Boolean(isTokenValid));

      if (!Boolean(isTokenValid)) return res.status(403).send("Unauthorized");

      cartCollection
        .insertOne({ ...serviceData, email: isTokenValid?.email })
        .then((result) => {
          if (result.insertedCount) {
            res.send({
              success: true,
              message: "Services Added To Cart Successfully",
            });
          }
        })
        .catch((serviceAddErr) => {
          res.status(500).send(serviceAddErr);
        });
    } catch (err) {
      console.log(err);
    }
  });
  // add to cart end

  // get cart items start

  app.get("/get-cart", async (req, res) => {
    const userToken = req.headers.authorization;

    if (!userToken.includes("Bearer ")) {
      return res.status(403).send("Unauthorized");
    }

    const token = userToken.split(" ")[1];

    try {
      const isTokenValid = await verifyToken(token);
      console.log(Boolean(isTokenValid));

      if (!Boolean(isTokenValid)) return res.status(403).send("Unauthorized");

      let searchQuery = {};

      if (isTokenValid.role !== "admin") {
        searchQuery = { email: isTokenValid.email };
      }

      const cart = await cartCollection.find(searchQuery);

      cart.toArray((cartErr, cartResult) => {
        console.log({ cartResult });
        if (cartErr !== null) {
          return res.status(500).send("something went wrong");
        }
        const ids = cartResult.map((c) => c.serviceId);
        console.log(ids);
        servicesCollection
          .find({
            _id: { $in: ids.map((id) => ObjectID(id)) },
          })
          .toArray((e, r) => {
            console.log(r.length);
            res.send(r);
          });
      });
    } catch (err) {
      console.log(err);
    }
  });

  // get cart items end

  // submit order start
  app.post("/submit-order", async (req, res) => {
    const userToken = req.headers.authorization;
    const productData = req.body;
    console.log(productData);

    if (!userToken.includes("Bearer ")) {
      return res.status(403).send("Unauthorized");
    }

    const token = userToken.split(" ")[1];

    try {
      const isTokenValid = await verifyToken(token);
      console.log(Boolean(isTokenValid));

      if (!Boolean(isTokenValid)) return res.status(403).send("Unauthorized");

      const userData = {
        userName: isTokenValid.userName,
        email: isTokenValid.email,
      };

      ordersCollection
        .insertOne({
          ...productData,
          ...userData,
          status: "pending",
          createdAt: new Date(),
        })
        .then((result) => {
          if (result.insertedCount) {
            res.send({
              success: true,
              message: "Order Submitted Successfully",
            });
          }
        })
        .catch((productAddErr) => {
          res.status(500).send(productAddErr);
        });
    } catch (err) {
      console.log(err);
    }
  });
  // submit order end

  // clear cart on submit start
  app.delete("/clear-cart", async (req, res) => {
    const userToken = req.headers.authorization;

    if (!userToken.includes("Bearer ")) {
      return res.status(403).send("Unauthorized");
    }

    const token = userToken.split(" ")[1];

    try {
      const isTokenValid = await verifyToken(token);
      console.log(Boolean(isTokenValid));

      if (!Boolean(isTokenValid)) return res.status(403).send("Unauthorized");

      console.log(isTokenValid.email);

      cartCollection
        .deleteMany({ email: isTokenValid?.email })
        .then((result) => {
          res.send({ success: true, deleted: result.deletedCount });
        })
        .catch((delErr) => {
          res.status(500).send(delErr);
        });
    } catch (err) {
      console.log(err);
    }
  });
  // clear cart on submit end

  // getOrder start
  app.get("/getOrders", async (req, res) => {
    const adminToken = req.headers.authorization;

    if (!adminToken.includes("Bearer ")) {
      return res.status(403).send("Unauthorized");
    }

    const token = adminToken.split(" ")[1];

    try {
      const isAdmin = await verifyToken(token);
      console.log(Boolean(isAdmin));

      if (!Boolean(isAdmin)) return res.status(403).send("Unauthorized");

      let searchQuery = {};

      if (isAdmin.role !== "admin") {
        searchQuery = { email: isAdmin.email };
      }

      ordersCollection.find(searchQuery).toArray((orderErr, orderResult) => {
        if (orderErr !== null) {
          return res.send({ success: false, msg: "something went wrong" });
        }
        res.send(orderResult);
      });
    } catch (error) {
      console.log(error);
    }
  });
  // getOrder end

  //update order status start
  app.patch("/update-order-status", async (req, res) => {
    const adminToken = req.headers.authorization;
    const { paymentId, status } = req.body;

    if (!adminToken.includes("Bearer ")) {
      return res.status(403).send("Unauthorized");
    }

    const token = adminToken.split(" ")[1];

    try {
      const isAdmin = await verifyToken(token);
      console.log(Boolean(isAdmin));

      if (!Boolean(isAdmin)) return res.status(403).send("Unauthorized");

      if (isAdmin.role !== "admin")
        return res.status(403).send("You have no permission to do that");

      console.log(paymentId, status);

      ordersCollection
        .findOneAndUpdate({ paymentId }, { $set: { status } })
        .then((data) => {
          console.log(data);
          res.send({
            success: true,
            message: `${status} Successfully`,
          });
        })
        .catch((updateError) => {
          res.status(500).send(updateError);
        });
    } catch (error) {
      console.log(error);
    }
  });
  //update order status end

  // submit review start
  app.post("/submit-review", async (req, res) => {
    //

    const userToken = req.headers.authorization;
    const reviewData = req.body;
    console.log(reviewData);

    if (!userToken.includes("Bearer ")) {
      return res.status(403).send("Unauthorized");
    }

    const token = userToken.split(" ")[1];

    try {
      const isTokenValid = await verifyToken(token);
      console.log(Boolean(isTokenValid));

      if (!Boolean(isTokenValid)) return res.status(403).send("Unauthorized");

      const reviewPerson = {
        userName: isTokenValid.userName,
        name: isTokenValid.name,
      };

      reviewCollection
        .insertOne({
          ...reviewData,
          ...reviewPerson,
          status: "pending",
          createdAt: new Date(),
        })
        .then((result) => {
          if (result.insertedCount) {
            res.send({
              success: true,
              message:
                "Review Submitted Successfully.Need Admin Approval To Show your review",
            });
          }
        })
        .catch((productAddErr) => {
          res.status(500).send(productAddErr);
        });
    } catch (err) {
      console.log(err);
    }

    //
  });
  // submit review end

  // get approved review start
  app.get("/get-approved-review", (req, res) => {
    reviewCollection.find({ status: "approved" }).toArray((rErr, rResult) => {
      if (rErr !== null) {
        return res.send(rErr);
      }
      return res.send(rResult);
    });
  });
  // get approved review end

  // get all review for admin start
  app.get("/get-all-review", async (req, res) => {
    const adminToken = req.headers.authorization;

    if (!adminToken.includes("Bearer ")) {
      return res.status(403).send("Unauthorized");
    }

    const token = adminToken.split(" ")[1];

    try {
      const isAdmin = await verifyToken(token);
      console.log(Boolean(isAdmin));

      if (!Boolean(isAdmin)) return res.status(403).send("Unauthorized");

      if (isAdmin.role !== "admin")
        return res.status(403).send("You have no permission to do that");

      reviewCollection.find({}).toArray((findError, usersResult) => {
        if (findError) return res.status(403).send(findError);
        res.send(usersResult);
      });
    } catch (error) {
      console.log(error);
    }
  });
  // get all review for admin end

  // review status update start
  app.post("/review-status-updater", async (req, res) => {
    const adminToken = req.headers.authorization;
    const { selectedStatus, _id } = req.body;

    if (!adminToken.includes("Bearer ")) {
      return res.status(403).send("Unauthorized");
    }

    const token = adminToken.split(" ")[1];

    try {
      const isAdmin = await verifyToken(token);
      console.log(Boolean(isAdmin));

      if (!Boolean(isAdmin)) return res.status(403).send("Unauthorized");

      if (isAdmin.role !== "admin")
        return res.status(403).send("You have no permission to do that");

      reviewCollection
        .findOneAndUpdate(
          { _id: ObjectID(_id) },
          { $set: { status: selectedStatus } }
        )
        .then((data) => {
          console.log(data);
          res.send({
            success: true,
            message: `${selectedStatus} Successfully`,
          });
        })
        .catch((updateError) => {
          console.log(updateError);
          res.status(500).send(updateError);
        });
    } catch (error) {
      console.log(error);
    }
  });
  // review status update end

  // make admin start
  app.get("/makeAdmin/:email", async (req, res) => {
    const adminToken = req.headers.authorization;
    const { email } = req.params;

    console.log(email);

    if (!adminToken.includes("Bearer ")) {
      return res.status(403).send("Unauthorized");
    }

    const token = adminToken.split(" ")[1];

    try {
      const isAdmin = await verifyToken(token);
      // console.log(Boolean(isAdmin));

      if (!Boolean(isAdmin)) return res.status(403).send("Unauthorized");

      if (isAdmin.role !== "admin")
        return res.status(403).send("You have no permission to do that");

      userCollection
        .findOne({ email })
        .then((isUserPresent) => {
          console.log({ isUserPresent });
          if (isUserPresent === null) {
            return res
              .status(404)
              .send({ success: "false", message: "user not found" });
          }

          userCollection
            .findOneAndUpdate({ email }, { $set: { role: "admin" } })
            .then((data) => {
              res.send({success:true,message:'promotion successful'})
            })
            .catch((makeAdminError) => {
              console.log(makeAdminError);
              res.status(500).send(makeAdminError);
            });
        })
        .catch((userFindErr) => {
          console.log(userFindErr);
        });
    } catch (error) {
      console.log(error);
    }
  });
  // make admin end
  console.log("I am connected Boss");
});

app.listen(port, () => {
  console.log("Hello Boss, I am running Now");
});