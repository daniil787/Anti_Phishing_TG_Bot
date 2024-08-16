import logging
import vt
import time
from telegram import Update, ForceReply
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# Enter API key of account VirusTotal
VIRUSTOTAL_API_KEY = ''

# Logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)
logger = logging.getLogger(__name__)
# Asynchronous function for checking URLs on VirusTotal
async def check_virustotal(url):
    try:
        async with vt.Client(VIRUSTOTAL_API_KEY) as client:
            url_id = vt.url_id(url)
            analysis_result = await client.get_object_async(f"/urls/{url_id}")
            return analysis_result
    except Exception as e:
        logger.error(f"Check URL error {url}: {e}")
        return None

# report about scanning
def generate_report(analysis_result):
    if not analysis_result:
        return "Couldn't get the results of the analysis."

    report = "Phishing сheck results:\n\n"
    positives = analysis_result.last_analysis_stats.get('malicious', 0)
    if positives > 0:
        report += f"Found {positives} THREATS!\n"
    else:
        report += "No threats found.\n"
    return report

# command /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    await update.message.reply_markdown_v2(
        fr'Hello {user.mention_markdown_v2()}\! Send link to check on phishing\.',
        reply_markup=ForceReply(selective=True),
    )

# Processing messages with links
async def analyze_link(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:

    start_time = time.time()

    url = update.message.text
    analysis_result = await check_virustotal(url)
    report = generate_report(analysis_result)

    end_time = time.time()

    elapsed_time = end_time - start_time
    report += f"\nExecution time: {elapsed_time:.2f} seconds"
    await update.message.reply_text(report)

def main() -> None:
    # Enter your Telegram bot token
    application = Application.builder().token("").build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, analyze_link))
    application.run_polling()

if __name__ == '__main__':
    main()
