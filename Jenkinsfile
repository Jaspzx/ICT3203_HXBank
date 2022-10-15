pipeline {
	agent any
	stages {
		stage('Checkout SCM') {
			steps {
				git 'git@github.com:ryangohsc/ICT3203_HXBank.git'
			}
		}

		stage('OWASP DependencyCheck') {
			steps {
				dependencyCheck additionalArguments: '--format HTML --format XML', odcInstallation: 'OWASP Dependency Check'
			}
		}
	}	
	post {
		success {
			dependencyCheckPublisher pattern: 'dependency-check-report.xml'
		}
	}
}