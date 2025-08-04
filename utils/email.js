import nodemailer from 'nodemailer';

export async function sendEmail(to, subject, text, html = null) {
    const EMAIL_USER = process.env.EMAIL_USER;
    const EMAIL_PASS = process.env.EMAIL_PASS;
    if (!EMAIL_USER || !EMAIL_PASS) {
        console.error('Email credentials not configured');
        return false;
    }
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: EMAIL_USER, pass: EMAIL_PASS },
    });

    try {
        console.log('[SEND EMAIL] Sending email with:');
        console.log('To:', to);
        console.log('Subject:', subject);
        console.log('Text:', text);
        console.log('HTML:', html ? '[HTML content present]' : '[No HTML]');
        const result = await transporter.sendMail({ from: EMAIL_USER, to, subject, text, html });
        console.log('[SEND EMAIL] Nodemailer result:', result);
        return true;
    } catch (error) {
        console.error('Lỗi gửi email:', error);
        return false;
    }
}

// Template email thông báo xóa tài khoản
export function createAccountDeletionEmail(userName, websiteName, deletionDate, reason, supportEmail, supportPhone) {
    const formattedDate = new Date(deletionDate).toLocaleString('vi-VN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });

    return `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9;">
            <div style="background-color: #ffffff; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h2 style="color: #333; text-align: center; margin-bottom: 30px;">Thông Báo Xóa Tài Khoản</h2>
                
                <p style="color: #555; font-size: 16px; line-height: 1.6;">
                    Chào <strong>${userName}</strong>,
                </p>
                
                <p style="color: #555; font-size: 16px; line-height: 1.6;">
                    Chúng tôi xác nhận rằng bạn đã yêu cầu xóa tài khoản tại <strong>${websiteName}</strong> vào <strong>${formattedDate}</strong>.
                </p>
                
                ${reason ? `<p style="color: #555; font-size: 16px; line-height: 1.6;">
                    <strong>Lý do:</strong> ${reason}
                </p>` : ''}
                
                <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #007bff;">
                    <p style="color: #333; font-size: 16px; line-height: 1.6; margin: 0;">
                        🔒 <strong>Tài khoản của bạn đã được tạm khóa (xóa mềm).</strong> Các dữ liệu như đơn hàng, đánh giá vẫn được giữ lại trong hệ thống trong vòng <strong>30 ngày</strong>.
                    </p>
                </div>
                
                <p style="color: #555; font-size: 16px; line-height: 1.6;">
                    Nếu bạn thay đổi ý định và muốn khôi phục tài khoản trong thời gian này, hãy liên hệ với chúng tôi tại:
                </p>
                
                <div style="background-color: #e8f4fd; padding: 15px; border-radius: 8px; margin: 15px 0;">
                    <p style="color: #333; font-size: 16px; line-height: 1.6; margin: 5px 0;">
                        📧 <strong>Email:</strong> ${supportEmail}
                    </p>
                    <p style="color: #333; font-size: 16px; line-height: 1.6; margin: 5px 0;">
                        📞 <strong>Điện thoại:</strong> ${supportPhone}
                    </p>
                </div>
                
                <p style="color: #555; font-size: 16px; line-height: 1.6;">
                    Cảm ơn bạn đã từng sử dụng dịch vụ của chúng tôi.
                </p>
                
                <p style="color: #555; font-size: 16px; line-height: 1.6;">
                    Thân mến,<br>
                    <strong>Đội ngũ ${websiteName}</strong>
                </p>
            </div>
        </div>
    `;
} 