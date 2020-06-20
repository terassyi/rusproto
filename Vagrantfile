Vagrant.configure("2") do |config|

  config.vm.box = "ubuntu/xenial64"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "1024"
  end
  config.vm.network "private_network", ip: "192.168.100.10"
  config.vm.synced_folder "./", "/home/vagrant/rusproto"
  config.vm.provision :shell, :path => "./install.sh"

end