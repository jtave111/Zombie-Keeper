# ===== Compiler =====
CXX      := g++
CXXFLAGS := -Wall -Wextra -Wpedantic -std=c++17 -g -MMD -MP

# ===== Directories =====
OBJ_DIR  := build
TARGET   := LocalFingerPrint

# ===== Automation (Local Files) =====
INC_DIRS := $(shell find . -type d -name "h")
SRCS := $(shell find . -path ./$(OBJ_DIR) -prune -o -name "*.cpp" -print)

# ===== Objects & Dependencies (Local) =====
OBJS := $(SRCS:./%.cpp=$(OBJ_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

# ===== EXTERNAL LIBRARY: PING =====
PING_SRC := ../ping/Ping.cpp
PING_OBJ := $(OBJ_DIR)/external/Ping.o

# ===== Include flags =====

INCLUDES := $(addprefix -I, $(INC_DIRS)) -I. -I../ping/h

# ===== Default =====
all: $(TARGET)

# ===== Link =====

$(TARGET): $(OBJS) $(PING_OBJ)
	@echo "🔨 Link: $@"
	@$(CXX) $(CXXFLAGS) $(OBJS) $(PING_OBJ) -o $@
	@echo "✅ Success!"

# ===== Compile Local Files =====
$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	@echo "⚙️  Compiling $<"
	@$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# ===== Compile External Ping =====

$(PING_OBJ): $(PING_SRC)
	@mkdir -p $(dir $@)
	@echo "⚙️  Compiling External Ping..."
	@$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# ===== Clean =====
clean:
	@rm -rf $(OBJ_DIR) $(TARGET)
	@echo "🧹 Clear."

# ===== Phony =====
.PHONY: all clean

-include $(DEPS)