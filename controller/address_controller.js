import response from "../utils/response.js";
import ShippingAddress from '../models/address_model.js'; //
import { validationResult } from 'express-validator';

const shippingAddress_controller = {

    addAddress: async (req, res) => {
        try {
            const userId = req.user.id;
            const { address, fullName, phoneNumber, ward, district, city, addressType = 'home', isDefault = false } = req.body;

            // Nếu địa chỉ mới được đặt làm mặc định, hủy đặt mặc định cho các địa chỉ cũ
            if (isDefault) {
                await ShippingAddress.updateMany({ userId: userId, isDefault: true }, { isDefault: false });
            }

            const newAddress = new ShippingAddress({
                userId,
                address,
                fullName,
                phoneNumber,
                ward,
                district,
                city,
                addressType,
                isDefault
            });

            await newAddress.save();
            return response(res, 201, 'Thêm địa chỉ giao hàng thành công', { address: newAddress });
        } catch (error) {
            console.error('Add address error:', error);
            // Có thể kiểm tra lỗi cụ thể hơn nếu muốn, ví dụ trùng lặp số điện thoại
            return response(res, 500, 'Lỗi server nội bộ');
        }
    },

    getAddresses: async (req, res) => {
        try {
            const userId = req.user.id;
            const addresses = await ShippingAddress.find({ userId, status: 'active' }).sort({ isDefault: -1, createdAt: -1 });
            return response(res, 200, 'Lấy danh sách địa chỉ giao hàng thành công', { addresses });
        } catch (error) {
            console.error('Get addresses error:', error);
            return response(res, 500, 'Lỗi server nội bộ');
        }
    },

    getAddressDetail: async (req, res) => {
        try {
            const { id } = req.params;
            const userId = req.user.id;

            const address = await ShippingAddress.findOne({ _id: id, userId, status: 'active' }); // Chỉ lấy địa chỉ active
            if (!address) {
                return response(res, 404, 'Địa chỉ không tồn tại hoặc không thuộc về người dùng này');
            }
            return response(res, 200, 'Lấy chi tiết địa chỉ thành công', { address });
        } catch (error) {
            console.error('Get address detail error:', error);
            return response(res, 500, 'Lỗi server nội bộ');
        }
    },

    updateAddress: async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return response(res, 400, 'Dữ liệu không hợp lệ', errors.array());
            }
            const { id } = req.params;
            const userId = req.user.id;
            const { address: newAddressText, fullName, phoneNumber, ward, district, city, addressType, isDefault } = req.body;
            const existingAddress = await ShippingAddress.findOne({ _id: id, userId, status: 'active' }); // Chỉ cập nhật địa chỉ active
            if (!existingAddress) {
                return response(res, 404, 'Địa chỉ không tồn tại hoặc không thuộc về người dùng này');
            }
            // Update fields if provided
            if (newAddressText !== undefined) existingAddress.address = newAddressText;
            if (fullName !== undefined) existingAddress.fullName = fullName;
            if (phoneNumber !== undefined) existingAddress.phoneNumber = phoneNumber;
            if (ward !== undefined) existingAddress.ward = ward;
            if (district !== undefined) existingAddress.district = district;
            if (city !== undefined) existingAddress.city = city;
            if (addressType !== undefined) existingAddress.addressType = addressType;

            if (isDefault === true) {
                await ShippingAddress.updateMany({ userId: userId, isDefault: true, _id: { $ne: id } }, { isDefault: false });
                existingAddress.isDefault = true;
            } else if (isDefault === false && existingAddress.isDefault === true) {
                // Nếu người dùng muốn bỏ đặt mặc định và nó đang là mặc định, bỏ đặt mặc định
                existingAddress.isDefault = false;
            }
            await existingAddress.save();
            return response(res, 200, 'Cập nhật địa chỉ giao hàng thành công', { address: existingAddress });
        } catch (error) {
            console.error('Update address error:', error);
            return response(res, 500, 'Lỗi server nội bộ');
        }
    },

    deleteAddress: async (req, res) => {
        try {
            const { id } = req.params;
            const userId = req.user.id;

            const addressToDelete = await ShippingAddress.findOne({ _id: id, userId, status: 'active' }); // Chỉ xóa địa chỉ active
            if (!addressToDelete) {
                return response(res, 404, 'Địa chỉ không tồn tại hoặc không thuộc về người dùng này');
            }

            if (addressToDelete.isDefault) {
                const otherAddresses = await ShippingAddress.find({ userId, _id: { $ne: id }, status: 'active' }); // Tìm địa chỉ active khác
                if (otherAddresses.length > 0) {
                    otherAddresses[0].isDefault = true;
                    await otherAddresses[0].save();
                } else {
                    return response(res, 400, 'Không thể xóa địa chỉ mặc định khi đây là địa chỉ duy nhất. Vui lòng thêm một địa chỉ khác trước.');
                }
            }
            await ShippingAddress.deleteOne({ _id: id, userId });
            return response(res, 200, 'Xóa địa chỉ giao hàng thành công');
        } catch (error) {
            console.error('Delete address error:', error);
            return response(res, 500, 'Lỗi server nội bộ');
        }
    }
};
export default shippingAddress_controller;