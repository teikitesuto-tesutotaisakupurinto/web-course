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
    userDoc.data().role !== "teacher" ||
    userDoc.data().disabled === true
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

    const className =
      typeof data.className === "string"
        ? data.className.trim().slice(0, 80)
        : "";

    const grade =
      typeof data.grade === "string"
        ? data.grade.trim().slice(0, 40)
        : "";

    const displayName =
      typeof data.displayName === "string"
        ? data.displayName.trim().slice(0, 120)
        : "";


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
          className,
          grade,
          displayName,
          disabled: false,
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
   生徒アカウント停止・再開
================================ */

exports.setUserDisabled = onCall(
  async (request) => {

    await requireTeacher(request);

    const userId = request.data?.userId;
    const disabled = request.data?.disabled;

    if(typeof userId !== "string" || !userId || typeof disabled !== "boolean"){
      throw new HttpsError(
        "invalid-argument",
        "対象ユーザーと停止状態を指定してください。"
      );
    }

    if(userId === request.auth.uid){
      throw new HttpsError(
        "failed-precondition",
        "自分のアカウントは停止できません。"
      );
    }

    const profileRef = db.collection("users").doc(userId);
    const profileSnapshot = await profileRef.get();
    if(!profileSnapshot.exists){
      throw new HttpsError("not-found", "ユーザーが見つかりません。");
    }
    if(profileSnapshot.data().role !== "student"){
      throw new HttpsError(
        "failed-precondition",
        "先生アカウントはこの画面から変更できません。"
      );
    }

    const profileUpdate = {
      disabled,
      disabledAt: disabled
        ? admin.firestore.FieldValue.serverTimestamp()
        : null,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    try{
      if(disabled)
        await profileRef.set(profileUpdate, { merge: true });

      await admin.auth().updateUser(userId, { disabled });

      if(disabled)
        await admin.auth().revokeRefreshTokens(userId);
      else
        await profileRef.set(profileUpdate, { merge: true });

      return { success: true, userId, disabled };
    }
    catch(error){
      console.error("生徒アカウント状態更新エラー", error);
      throw new HttpsError(
        "internal",
        "アカウント状態を更新できませんでした。"
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
        ["image", "video", "raw"].includes(data.resourceType)
          ? data.resourceType
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


/* ================================
   QRログイン
================================ */

exports.issueQrLogin = onCall(
  async (request) => {
    await requireTeacher(request);

    const userId = request.data?.userId;
    if (typeof userId !== "string" || !userId) {
      throw new HttpsError("invalid-argument", "ユーザーを指定してください。");
    }

    const userDoc = await db.collection("users").doc(userId).get();
    if (!userDoc.exists) {
      throw new HttpsError("not-found", "ユーザーが見つかりません。");
    }
    if (userDoc.data().disabled === true) {
      throw new HttpsError("failed-precondition", "停止中のアカウントにはログインQRを発行できません。");
    }

    const ticket = crypto.randomBytes(32).toString("base64url");
    const ticketId = crypto.createHash("sha256").update(ticket).digest("hex");

    await db.collection("qrLoginTickets").doc(ticketId).create({
      uid: userId,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    return { ticket };
  }
);


exports.redeemQrLogin = onCall(
  async (request) => {
    const ticket = request.data?.ticket;
    if (typeof ticket !== "string" || !/^[A-Za-z0-9_-]{40,60}$/.test(ticket)) {
      throw new HttpsError("invalid-argument", "QRコードが正しくありません。");
    }

    const ticketId = crypto.createHash("sha256").update(ticket).digest("hex");
    const ticketRef = db.collection("qrLoginTickets").doc(ticketId);
    const uid = await db.runTransaction(async (transaction) => {
      const ticketDoc = await transaction.get(ticketRef);
      if (!ticketDoc.exists) {
        throw new HttpsError("permission-denied", "QRコードは無効です。");
      }

      const data = ticketDoc.data();
      if (data.usedAt) {
        throw new HttpsError("permission-denied", "QRコードは使用済みです。");
      }

      transaction.update(ticketRef, {
        usedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      return data.uid;
    });

    const customToken = await admin.auth().createCustomToken(uid);
    return { customToken };
  }
);
