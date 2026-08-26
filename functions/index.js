const {
  onCall,
  HttpsError
} = require("firebase-functions/v2/https");

const {
  defineSecret
} = require("firebase-functions/params");

const admin = require("firebase-admin");
const crypto = require("crypto");

admin.initializeApp();

const db = admin.firestore();

const CLOUDINARY_CLOUD_NAME =
  defineSecret("CLOUDINARY_CLOUD_NAME");

const CLOUDINARY_API_KEY =
  defineSecret("CLOUDINARY_API_KEY");

const CLOUDINARY_API_SECRET =
  defineSecret("CLOUDINARY_API_SECRET");


/* ================================
   先生・管理者チェック
================================ */

async function requireTeacher(request) {

  if (!request.auth) {
    throw new HttpsError(
      "unauthenticated",
      "ログインしてください。"
    );
  }

  const userDoc = await db
    .collection("users")
    .doc(request.auth.uid)
    .get();

  if (
    !userDoc.exists ||
    userDoc.data().role !== "teacher"
  ) {
    throw new HttpsError(
      "permission-denied",
      "先生・管理者のみ利用できます。"
    );
  }
}


/* ================================
   ユーザー作成
================================ */

exports.createUser = onCall(
  async (request) => {

    await requireTeacher(request);

    const data = request.data || {};

    const email =
      typeof data.email === "string"
        ? data.email.trim()
        : "";

    const password =
      typeof data.password === "string"
        ? data.password
        : "";

    const role = data.role;


    if (!email) {
      throw new HttpsError(
        "invalid-argument",
        "メールアドレスを入力してください。"
      );
    }


    if (password.length < 6) {
      throw new HttpsError(
        "invalid-argument",
        "パスワードは6文字以上にしてください。"
      );
    }


    if (
      role !== "student" &&
      role !== "teacher"
    ) {
      throw new HttpsError(
        "invalid-argument",
        "権限が正しくありません。"
      );
    }


    try {

      const newUser =
        await admin.auth().createUser({
          email,
          password
        });


      await db
        .collection("users")
        .doc(newUser.uid)
        .set({
          email,
          role,
          createdAt:
            admin.firestore.FieldValue.serverTimestamp()
        });


      return {
        success: true,
        uid: newUser.uid,
        email,
        role
      };

    } catch (error) {

      console.error(error);

      if (
        error.code ===
        "auth/email-already-exists"
      ) {
        throw new HttpsError(
          "already-exists",
          "このメールアドレスは既に登録されています。"
        );
      }


      if (
        error.code ===
        "auth/invalid-email"
      ) {
        throw new HttpsError(
          "invalid-argument",
          "メールアドレスが正しくありません。"
        );
      }


      throw new HttpsError(
        "internal",
        "ユーザーを作成できませんでした。"
      );
    }
  }
);


/* ================================
   Cloudinary署名
================================ */

exports.getCloudinaryUploadSignature =
  onCall(
    {
      secrets: [
        CLOUDINARY_CLOUD_NAME,
        CLOUDINARY_API_KEY,
        CLOUDINARY_API_SECRET
      ]
    },

    async (request) => {

      await requireTeacher(request);

      const data =
        request.data || {};


      const resourceType =
        data.resourceType === "image"
          ? "image"
          : "video";


      let folder =
        typeof data.folder === "string"
          ? data.folder
          : "web-course/videos";


      if (
        !folder.startsWith("web-course/")
      ) {
        folder =
          "web-course/videos";
      }


      const timestamp =
        Math.floor(
          Date.now() / 1000
        );


      const params = {
        folder,
        timestamp
      };


      const signatureText =
        Object.keys(params)
          .sort()
          .map(
            key =>
              `${key}=${params[key]}`
          )
          .join("&");


      const signature =
        crypto
          .createHash("sha1")
          .update(
            signatureText +
            CLOUDINARY_API_SECRET.value()
          )
          .digest("hex");


      return {

        success: true,

        cloudName:
          CLOUDINARY_CLOUD_NAME.value(),

        apiKey:
          CLOUDINARY_API_KEY.value(),

        timestamp,

        folder,

        signature,

        resourceType

      };

    }
  );
