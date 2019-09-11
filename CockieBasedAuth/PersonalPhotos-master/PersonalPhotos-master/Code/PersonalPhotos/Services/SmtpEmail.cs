using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using PersonalPhotos.Interfaces;

namespace PersonalPhotos.Services
{
    public class SmtpEmail : IEmail
    {
        private readonly EmailOptions _options;
        public SmtpEmail(IOptions<EmailOptions> options)
        {
            this._options = options.Value;
        }

        public async Task Send(string emailAddress, string body)
        {
            var client = new SmtpClient();
            client.Host = this._options.Host;
            client.Credentials = new NetworkCredential(_options.UserName, _options.Password);

            var message = new MailMessage("rxkolegata@mail.bg", emailAddress);
            message.Body = body;
            message.IsBodyHtml = true;

            await client.SendMailAsync(message);
        }
    }
}
