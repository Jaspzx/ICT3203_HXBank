pipeline {
	agent any
	stages {
		stage('Build') {
			steps {
					script{
					    sh 'docker container rm -f flask'
                        sh 'docker image rm -f flask'
                        sh 'docker build -t flask .'
					}
			}
		}
		stage('Test') {
			steps {
				sh 'python3 -m xmlrunner discover -s webportal/unit_tests/ -p  unit_tests.py -o webportal/unit_tests/result'
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
                    withCredentials([file(credentialsId: 'env', variable: 'env_file')]) {
                       sh 'docker container run -d --expose 5000 -v /home/Team-13/webportal/ICT3203_HXBank/db/:/etc/certs/ -w /app --env-file $env_file --network HXBank_bridge --ip 172.30.0.2 --network-alias flask --name flask flask'
                    }
                }
            }
        }
	}	
	post {
		success {
		    junit skipPublishingChecks: true, testResults: '/var/jenkins_home/workspace/hxbankpipeline/webportal/unit_tests/result/*.xml'
			dependencyCheckPublisher pattern: '/var/jenkins_home/workspace/hxbankpipeline/dependency-check-report.xml'
		}
	}
}
