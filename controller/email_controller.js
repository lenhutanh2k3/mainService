import { sendEmail } from '../utils/email.js';
import response from '../utils/response.js';

const email_controller = {
    // Gửi email thông báo đơn hàng tạo thành công
    sendOrderConfirmation: async (req, res, next) => {
        try {
            const { to, orderCode, paymentMethod, totalAmount, shippingAddress, subject, html } = req.body;

            // Nếu có html thì chỉ cần to và subject
            if (html) {
                if (!to || !subject) {
                    throw new Error('Email và tiêu đề là bắt buộc khi gửi email HTML');
                }
                const success = await sendEmail(to, subject, '', html);
                if (success) {
                    return response(res, 200, 'Email thông báo đã được gửi thành công', {
                        emailSent: true,
                        success: true
                    });
                } else {
                    throw new Error('Không thể gửi email thông báo');
                }
            }
            // Nếu không có html thì kiểm tra các trường cũ
            if (!to || !orderCode) {
                throw new Error('Email và mã đơn hàng là bắt buộc');
            }
            const fallbackSubject = 'Đơn hàng đã được tạo thành công';
            let text = `Đơn hàng ${orderCode} đã được tạo thành công.\n\n`;
            text += `Tổng tiền: ${totalAmount?.toLocaleString('vi-VN')} VNĐ\n`;
            if (shippingAddress) {
                text += `Địa chỉ giao hàng: ${shippingAddress.address}, ${shippingAddress.ward}, ${shippingAddress.district}, ${shippingAddress.city}\n`;
            }
            if (paymentMethod === 'COD') {
                text += '\nPhương thức thanh toán: Thanh toán khi nhận hàng (COD)\n';
                text += 'Vui lòng chuẩn bị tiền mặt khi nhận hàng.';
            } else if (paymentMethod === 'VNPAY') {
                text += '\nPhương thức thanh toán: VNPAY\n';
                text += 'Vui lòng hoàn tất thanh toán để đơn hàng được xử lý.';
            }
            const success = await sendEmail(to, subject || fallbackSubject, text);
            if (success) {
                return response(res, 200, 'Email thông báo đã được gửi thành công', {
                    orderCode,
                    emailSent: true,
                    success: true
                });
            } else {
                throw new Error('Không thể gửi email thông báo');
            }
        } catch (error) {
            next(error);
        }
    },
    // Gửi email thông báo trạng thái đơn hàng
    sendOrderStatusUpdate: async (req, res, next) => {
        try {
            const { to, orderCode, status, additionalInfo, subject, html } = req.body;

            // Nếu có html thì chỉ cần to và subject
            if (html) {
                if (!to || !subject) {
                    throw new Error('Email và tiêu đề là bắt buộc khi gửi email HTML');
                }
                const success = await sendEmail(to, subject, '', html);
                if (success) {
                    return response(res, 200, 'Email thông báo đã được gửi thành công', {
                        emailSent: true,
                        success: true
                    });
                } else {
                    throw new Error('Không thể gửi email thông báo');
                }
            }

            // Fallback nếu không có html
            if (!to || !orderCode || !status) {
                throw new Error('Email, mã đơn hàng và trạng thái là bắt buộc');
            }

            let text = `Đơn hàng ${orderCode} `;
            let emailSubject = subject;
            switch (status) {
                case 'CONFIRMED':
                    emailSubject = emailSubject || 'Đơn hàng đã được xác nhận';
                    text += 'đã được xác nhận và đang được chuẩn bị để giao hàng.';
                    break;
                case 'SHIPPING':
                    emailSubject = emailSubject || 'Đơn hàng đang được giao';
                    text += 'đang được giao đến địa chỉ của bạn.';
                    break;
                case 'DELIVERED':
                    emailSubject = emailSubject || 'Đơn hàng đã được giao thành công';
                    text += 'đã được giao thành công. Cảm ơn bạn đã mua hàng!';
                    break;
                case 'CANCELLED':
                    emailSubject = emailSubject || 'Đơn hàng đã bị hủy';
                    text += 'đã được hủy.';
                    if (additionalInfo) {
                        text += `\nLý do: ${additionalInfo}`;
                    }
                    break;
                default:
                    emailSubject = emailSubject || 'Cập nhật trạng thái đơn hàng';
                    text += `đã được cập nhật trạng thái: ${status}`;
            }
            const success = await sendEmail(to, emailSubject, text);

            if (success) {
                return response(res, 200, 'Email thông báo đã được gửi thành công', {
                    orderCode,
                    status,
                    emailSent: true,
                    success: true
                });
            } else {
                throw new Error('Không thể gửi email thông báo');
            }
        } catch (error) {
            next(error);
        }
    },
    // Gửi email thông báo thanh toán
    sendPaymentNotification: async (req, res, next) => {
        try {
            const { to, orderCode, paymentStatus, amount, paymentMethod } = req.body;

            if (!to || !orderCode || !paymentStatus) {
                throw new Error('Email, mã đơn hàng và trạng thái thanh toán là bắt buộc');
            }

            let subject = '';
            let text = `Đơn hàng ${orderCode} - `;

            switch (paymentStatus) {
                case 'PAID':
                    subject = 'Thanh toán thành công';
                    text += 'đã được thanh toán thành công.\n';
                    text += `Số tiền: ${amount?.toLocaleString('vi-VN')} VNĐ\n`;
                    text += `Phương thức: ${paymentMethod || 'Không xác định'}`;
                    break;
                case 'FAILED':
                    subject = 'Thanh toán thất bại';
                    text += 'thanh toán thất bại. Vui lòng thử lại hoặc liên hệ hỗ trợ.';
                    break;
                case 'PENDING':
                    subject = 'Thanh toán đang chờ xử lý';
                    text += 'thanh toán đang được xử lý. Vui lòng chờ trong giây lát.';
                    break;
                default:
                    subject = 'Cập nhật trạng thái thanh toán';
                    text += `trạng thái thanh toán: ${paymentStatus}`;
            }

            const success = await sendEmail(to, subject, text);

            if (success) {
                return response(res, 200, 'Email thông báo thanh toán đã được gửi thành công', {
                    orderCode,
                    paymentStatus,
                    emailSent: true,
                    success: true
                });
            } else {
                throw new Error('Không thể gửi email thông báo');
            }
        } catch (error) {
            next(error);
        }
    }
};

export default email_controller; 