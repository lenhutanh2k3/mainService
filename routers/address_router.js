import express from 'express';
import shippingAddress_controller from '../controller/address_controller.js'; //
import {
    check_Token,
    check_authenticated_user 
} from '../middleware/auth_middleware.js'; 

import {
    validateShippingAddress,
    validateUpdateShippingAddress
} from '../middleware/validate_middleware.js' 

const address_router = express.Router();
address_router.use(check_Token);

// Các route quản lý địa chỉ (chỉ cần người dùng đã đăng nhập)
address_router.post('/', check_authenticated_user, validateShippingAddress, shippingAddress_controller.addAddress);
address_router.get('/', check_authenticated_user, shippingAddress_controller.getAddresses);
address_router.get('/:id', check_authenticated_user, shippingAddress_controller.getAddressDetail);
address_router.put('/:id', check_authenticated_user, validateUpdateShippingAddress, shippingAddress_controller.updateAddress);
address_router.delete('/:id', check_authenticated_user, shippingAddress_controller.deleteAddress);

export default address_router;