using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TSPacketEditor.Config
{
    public class Config
    {
        public bool EnableMatching { get; set; }
        public List<MatchCommand> MatchCommands { get; set; } = new List<MatchCommand>();

        public Config()
        {

        }
    }
}
