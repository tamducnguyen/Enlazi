export const message = {
  user: {
    exist: 'Email này đã được đăng ký.',
    send_code_successfully: 'Đã gửi mã xác minh. Vui lòng kiểm tra email.',
    verify_successfully: 'Tài khoản của bạn đã được xác minh.',
    not_exist: 'Thông tin xác minh không hợp lệ. Vui lòng thử lại.',
    already_verified: 'Tài khoản của bạn đã được xác minh rồi.',
    wrong_verified_code: 'Mã xác minh không chính xác.',
    not_active: 'Tài khoản của bạn chưa được kích hoạt.',
    invalid_email_password: 'Email hoặc mật khẩu không đúng. Vui lòng thử lại.',
    role_not_exist: 'Thông tin vai trò không hợp lệ.',
    sign_out_successfully: 'Đăng xuất thành công.',
    sign_in_successfully: 'Đăng nhập thành công.',
    refresh_token_successfully: 'Làm mới phiên đăng nhập thành công.',
    reset_password_successfully: 'Đặt lại mật khẩu thành công.',
    forbidden: 'Từ chối truy cập. Đường dẫn không hợp lệ.',
    userbanned:
      'Tài khoản của bạn tạm thời bị khóa. Vui lòng thử lại sau 5 phút.',
    sign_in_with_google_successfully: 'Đăng nhập bằng Google thành công.',
    wait_before_resend: 'Vui lòng đợi 60 giây trước khi yêu cầu gửi lại email.',
    not_support_change_password: 'Tài khoản của bạn không hỗ trợ đổi mật khẩu.',
    must_not_same_password: 'Mật khẩu mới phải khác mật khẩu cũ.',
    change_password_successfully: 'Đổi mật khẩu thành công.',
    invalid_credentials: 'Thông tin xác thực không hợp lệ.',
    confirm_password_not_match: 'Mật khẩu mới và xác nhận mật khẩu không khớp.',
    invalid_payload_token: 'Thông tin xác thực (token) không hợp lệ.',
    get_profile_successfully: 'Lấy hồ sơ người dùng thành công.',
    get_hobbies_successfully: 'Lấy danh sách sở thích thành công.',
    not_found_some_hobbies: 'Không tìm thấy một số sở thích được yêu cầu.',
    update_hobbies_successfully: 'Cập nhật sở thích thành công.',
  },
  auth: {
    ratelimit: {
      too_many_requests: 'Quá nhiều yêu cầu. Vui lòng thử lại sau.',
    },
    refresh_token: {
      invalid_or_expired: 'Refresh token không hợp lệ hoặc đã hết hạn.',
      missing: 'Thiếu refresh token. Vui lòng thử lại.',
      not_match_cookie_between_body:
        'Refresh token không khớp. Vui lòng thử lại.',
    },
  },
  google_auth_error: {
    id_token_missing: 'Google không trả về id_token.',
    invalid_token: 'Google token không hợp lệ.',
    email_not_verified: 'Email chưa được Google xác minh.',
  },
};
export const prefix_key_cached = {
  verify_code: 'auth:email-code:',
  forgot_password_code: 'forgotpassword:email-code:',
  number_verified: 'number_verified:email-code:',
  userbanned: 'userbanned:email:',
  signupinfo: 'signupinfo:email:',
  sendmail: 'sendmail:email:',
};
export const ttlCache = 5 * 60 * 1000;
export const ttlCacheEmail = 60 * 1000;
export const cookieOptions = {
  name: {
    accessToken: 'accessToken',
    refreshToken: 'refreshToken',
    sessionId: 'sessionId',
  },
  maxAge: {
    accessToken: 60 * 60 * 1000, //1hour
    refreshToken: 365 * 24 * 60 * 60 * 1000, //1year
    sessionId: 365 * 24 * 60 * 60 * 1000, //1year
  },
  sameSite: 'strict',
};
