## EvaluatingCSA

در این برنامه شش مدل از شبکه سازمانی طراحی شده است که در فایل های YML در بخش BPMN-Network_Model/Model{Number}/model{number}.yml قرار دارند.
می توان مدل های بیشتر را نیز به همین ترتیب اضافه کرد.

در این برنامه چهار شبیه ساز از سیستم های آگاهی از وضعیت امنیت سایبری ایجاد شده است که هر فایل مدل را می خواند و در هر گره از گراف حمله گره فعلی، گره بعدی و مسیر حمله را تعیین و پیشبینی می کند. در هر گره ضریب کسب و کار فعلی و آینده را نیز مشخص می کند.

در نهایت در MongoDB مجموعه داده غیر جدولی و در فایل های CSV مجموعه داده جدولی ایجاد می شود. گراف ها و جداول نتایج نیز برای نتیجه گیری ایجاد می شود.

برای اجرای کد ابتدا نیاز داریم که یک virtual environment در پایتون بسازیم. سپس پکیج هایی که در فایل requirements.txt وجود دارد را در این محیط نصب کنیم. همچنین نیاز داریم که MongoDb در سیستم نصب باشد.

ابتدا فایل python main.py را اجرا می کنیم و صبر می کنیم تا به ازای هر مدل به 100 درصد برسد. ممکن است چندین دقیقه طول بکشد. در این مرحله مجموعه داده غیر جدولی آماده می شود.

سپس فایل main2.py را با دستور python main2.py اجرا می کنیم. این مرحله سریعتر اجرا می شود. در این بخش مجموعه داده جدولی و گراف ها و جداول ساخته می شوند.



In this program, six models of the organizational network have been designed, which are located in the YML files under the BPMN-Network_Model/Model{Number}/model{number}.yml directory.
More models can be added in the same manner.

In this program, four simulators of cybersecurity situational awareness systems have been created. Each simulator reads a model file and, at each node of the attack graph, determines and predicts the current node, the next node, and the attack path. At each node, it also specifies the current and future business coefficients.

Finally, a non-relational dataset is created in MongoDB, and a relational dataset is generated in CSV files. Graphs and result tables are also created for conclusions.

To run the code, first we need to create a virtual environment in Python. Then install the packages listed in the requirements.txt file into this environment. MongoDB also needs to be installed on the system.

First, run the python file main.py and wait until it reaches 100% for each model. This may take several minutes. At this stage, the non-relational dataset is prepared.

Then run the file main2.py with the command python main2.py. This step runs faster. In this phase, the relational dataset, graphs, and tables are created