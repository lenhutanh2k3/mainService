import user_router from "./user_router.js";
import address_router from "./address_router.js";
import email_router from "./email_router.js";
import review_router from "./review_router.js";


const router = (app) => {
    app.use('/api/users', user_router);
    app.use('/api/address', address_router);
    app.use('/api/email', email_router);
    app.use('/api/reviews', review_router);

}
export default router;