pipeline {
	agent any
	stages {
		stage('Build') {
			steps {
					script{
					    sh 'docker container rm -f ict3203_hxbank-flask'
                        sh 'docker image rm -f hxbankwebsite'
                        sh 'docker build -t ict3203_hxbank-flask .'
					}
				echo 'Build phase success'
			}
		}
		stage('Test') {
			steps {
				echo 'Testing'
			}
		}
		stage('OWASP DependencyCheck') {
			steps {
				dependencyCheck additionalArguments: '--format HTML --format XML', odcInstallation: 'OWASP Dependency Check'
			}
		}

		stage ('Deploy') {
            steps {
                script{
                    sh 'docker run -d -e VIRTUAL_HOST=hxbank.tk  -e VIRTUAL_PORT=5000 --name ict3203_hxbank-flask ict3203_hxbank-flask
                    --env-file .env'
                }
            }
        }
	}	
	post {
		success {
			dependencyCheckPublisher pattern: 'dependency-check-report.xml'
		}
	}
}